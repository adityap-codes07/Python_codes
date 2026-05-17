"""
Malicious URL Detector — Improved Single-File Edition
======================================================
Improvements over original:
  • Logging instead of bare print/exceptions
  • Caching for Alexa / Safe Browsing results (TTL-based, in-memory)
  • Richer feature set: entropy, special-char counts, TLD suspicion, URL shortener flag,
    HTTPS flag, number-of-subdomains, path depth
  • Thread-safe model loading / lazy init
  • Graceful degradation when optional deps (pygeoip) are absent
  • CLI: batch prediction from a text file
  • GUI: colour-coded result labels, history list
  • Type hints throughout
"""

from __future__ import annotations

import csv
import json
import logging
import math
import os
import re
import sys
import argparse
import threading
import time
import urllib.request
import webbrowser
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from xml.dom import minidom

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import joblib

# GUI (standard library)
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Optional
try:
    import pygeoip  # pip install pygeoip
    _PYGEOIP_OK = True
except ImportError:
    pygeoip = None  # type: ignore
    _PYGEOIP_OK = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("url_detector")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NF = -1
DEFAULT_TRAIN_CSV   = "url_features.csv"
DEFAULT_TEST_CSV    = "test_features.csv"
DEFAULT_MODEL_PATH  = "rf_model.joblib"

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()

# Known URL-shortener hostnames
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "buff.ly", "is.gd", "rebrand.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "bl.ink",
}

# TLDs often abused in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".xyz", ".top", ".club", ".online", ".site", ".win",
}

SECURITY_WORDS = {
    "confirm", "account", "banking", "secure", "ebayisapi",
    "webscr", "login", "signin", "update", "verify", "auth",
    "password", "credential",
}

# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class _TTLCache:
    """Thread-safe in-memory TTL cache."""

    def __init__(self, maxsize: int = 512, ttl: float = 3600.0):
        self._store: OrderedDict = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, ts = entry
            if time.time() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.time())
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)


_alexa_cache      = _TTLCache(ttl=86400)
_sb_cache         = _TTLCache(ttl=3600)
_model_lock       = threading.Lock()
_loaded_model_pkg = None  # cached after first load

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_int(x, default: int = NF) -> int:
    try:
        if x is None or (isinstance(x, str) and not x.strip()):
            return default
        return int(float(x))
    except Exception:
        return default


def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _tokenise(text: str) -> Tuple[float, float, float]:
    """Return (avg_len, count, max_len) of alphanumeric tokens."""
    if not text:
        return 0.0, 0.0, 0.0
    parts = [p for p in re.split(r"\W+", text) if p]
    if not parts:
        return 0.0, 0.0, 0.0
    lengths = [len(p) for p in parts]
    return sum(lengths) / len(lengths), float(len(parts)), float(max(lengths))


def _security_word_count(tokens: List[str]) -> int:
    return sum(1 for t in tokens if t in SECURITY_WORDS)


def _has_exe(url: str) -> int:
    return 1 if ".exe" in url.lower() else 0


def _looks_like_ip(host: str) -> int:
    ip4 = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    return 1 if ip4.match(host or "") else 0


def _count_special(url: str) -> Tuple[int, int, int, int]:
    """Return (hyphens, at_signs, double_slashes, percent_signs)."""
    return (
        url.count("-"),
        url.count("@"),
        url.count("//"),
        url.count("%"),
    )


def _is_url_shortener(host: str) -> int:
    return 1 if (host or "").lower() in URL_SHORTENERS else 0


def _suspicious_tld(host: str) -> int:
    host = (host or "").lower()
    return 1 if any(host.endswith(t) for t in SUSPICIOUS_TLDS) else 0


def _subdomain_count(host: str) -> int:
    if not host:
        return 0
    parts = host.split(".")
    # e.g. "a.b.com" → 1 subdomain; "com" alone → 0
    return max(0, len(parts) - 2)


def _path_depth(path: str) -> int:
    if not path:
        return 0
    parts = [p for p in path.split("/") if p]
    return len(parts)


def _find_ele_with_attribute(dom, ele: str, attribute: str) -> Any:
    for el in dom.getElementsByTagName(ele):
        if el.hasAttribute(attribute):
            return el.attributes[attribute].value
    return NF


def _site_popularity_alexa(host: str) -> Tuple[int, int]:
    if not host:
        return NF, NF
    cached = _alexa_cache.get(host)
    if cached is not None:
        return cached
    try:
        url = "http://data.alexa.com/data?cli=10&dat=snbamz&url=" + host
        with urllib.request.urlopen(url, timeout=7) as resp:
            dom = minidom.parse(resp)
        rank_host    = _safe_int(_find_ele_with_attribute(dom, "REACH",   "RANK"))
        rank_country = _safe_int(_find_ele_with_attribute(dom, "COUNTRY", "RANK"))
        result = (rank_host, rank_country)
    except Exception:
        result = (NF, NF)
    _alexa_cache.set(host, result)
    return result


def _get_asn(host: str) -> int:
    if not host or not _PYGEOIP_OK:
        return NF
    db_path = "GeoIPASNum.dat"
    if not os.path.exists(db_path):
        return NF
    try:
        g   = pygeoip.GeoIP(db_path)
        org = g.org_by_name(host) or ""
        first = org.split()[0] if org else ""
        if first.startswith("AS"):
            return _safe_int(first[2:])
    except Exception:
        pass
    return NF


def _safe_browsing_check(url: str) -> int:
    if not SAFE_BROWSING_API_KEY:
        return NF
    cached = _sb_cache.get(url)
    if cached is not None:
        return cached
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {"clientId": "url-detector", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode()
        result = 1 if "matches" in data else 0
    except Exception:
        result = NF
    _sb_cache.set(url, result)
    return result


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------
def extract_features(url: str) -> Dict[str, Any]:
    url     = (url or "").strip()
    parsed  = urlparse(url)
    host    = parsed.netloc
    path    = parsed.path
    query   = parsed.query

    tokens  = [t for t in re.split(r"\W+", url.lower()) if t]

    rank_host, rank_country = _site_popularity_alexa(host)

    avg_url,  cnt_url,  max_url  = _tokenise(url)
    avg_dom,  cnt_dom,  max_dom  = _tokenise(host)
    avg_path, cnt_path, max_path = _tokenise(path)

    hyphens, at_signs, dbl_slash, pct_signs = _count_special(url)

    return {
        # Meta
        "URL":              url,
        "host":             host,
        "path":             path,
        # Popularity
        "rank_host":        rank_host,
        "rank_country":     rank_country,
        # Length features
        "url_length":       len(url),
        "host_length":      len(host),
        "path_length":      len(path),
        "query_length":     len(query),
        "no_of_dots":       url.count("."),
        # Token features
        "avg_url_token_len":  avg_url,
        "url_token_count":    cnt_url,
        "largest_url_token":  max_url,
        "avg_dom_token_len":  avg_dom,
        "dom_token_count":    cnt_dom,
        "largest_dom_token":  max_dom,
        "avg_path_token_len": avg_path,
        "path_token_count":   cnt_path,
        "largest_path_token": max_path,
        # Security-word count
        "sec_word_cnt":       _security_word_count(tokens),
        # Structural flags
        "ip_presence":        _looks_like_ip(host),
        "exe_in_url":         _has_exe(url),
        "is_https":           1 if parsed.scheme == "https" else 0,
        "is_shortener":       _is_url_shortener(host),
        "suspicious_tld":     _suspicious_tld(host),
        "subdomain_count":    _subdomain_count(host),
        "path_depth":         _path_depth(path),
        # Special-char counts
        "hyphen_count":       hyphens,
        "at_sign_count":      at_signs,
        "double_slash_count": dbl_slash,
        "percent_count":      pct_signs,
        # Entropy
        "url_entropy":        round(_entropy(url),  4),
        "host_entropy":       round(_entropy(host), 4),
        "path_entropy":       round(_entropy(path), 4),
        # ASN / Safe Browsing
        "ASNno":              _get_asn(host),
        "safebrowsing":       _safe_browsing_check(url),
    }


def write_csv(rows: List[Dict[str, Any]], out_csv: str) -> None:
    if not rows:
        return
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# ML helpers
# ---------------------------------------------------------------------------
_EXCLUDE_COLS = {"URL", "host", "path", "malicious", "result", "label"}


def _feature_cols(df: pd.DataFrame) -> List[str]:
    return [c for c in df.columns if c not in _EXCLUDE_COLS]


def train_model(
    train_csv: str  = DEFAULT_TRAIN_CSV,
    model_path: str = DEFAULT_MODEL_PATH,
    n_estimators: int = 200,
    cv: int = 0,
) -> RandomForestClassifier:
    if not os.path.exists(train_csv):
        raise FileNotFoundError(f"Training CSV not found: {train_csv}")

    df = pd.read_csv(train_csv)
    if "malicious" not in df.columns:
        raise ValueError("Training CSV must have a 'malicious' column (0 = safe, 1 = malicious).")

    cols = _feature_cols(df)
    X    = df[cols].apply(pd.to_numeric, errors="coerce").fillna(NF)
    y    = df["malicious"].apply(_safe_int)

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
    )

    if cv > 1:
        scores = cross_val_score(model, X, y, cv=cv, scoring="f1")
        log.info("CV F1 scores: %s  mean=%.4f", scores.round(4), scores.mean())

    model.fit(X, y)
    joblib.dump({"model": model, "train_cols": cols}, model_path)
    log.info("Model saved → %s  (features: %d)", model_path, len(cols))
    return model


def _load_model_pkg(model_path: str = DEFAULT_MODEL_PATH) -> Optional[Dict]:
    global _loaded_model_pkg
    with _model_lock:
        if _loaded_model_pkg is None:
            if not os.path.exists(model_path):
                return None
            _loaded_model_pkg = joblib.load(model_path)
    return _loaded_model_pkg


def predict_url(
    url: str,
    train_csv:  str = DEFAULT_TRAIN_CSV,
    test_csv:   str = DEFAULT_TEST_CSV,
    model_path: str = DEFAULT_MODEL_PATH,
) -> int:
    """Return 0 (safe) or 1 (malicious)."""
    row = extract_features(url)
    write_csv([row], test_csv)

    pkg = _load_model_pkg(model_path)
    if pkg is None:
        log.info("No saved model found — training now…")
        train_model(train_csv, model_path)
        pkg = _load_model_pkg(model_path)

    model      = pkg["model"]
    train_cols = pkg["train_cols"]

    test_df = pd.read_csv(test_csv)
    # Align columns — add missing as NF
    for col in train_cols:
        if col not in test_df.columns:
            test_df[col] = NF
    Xq = test_df[train_cols].apply(pd.to_numeric, errors="coerce").fillna(NF)

    return int(model.predict(Xq)[0])


def predict_batch(
    urls: List[str],
    train_csv:  str = DEFAULT_TRAIN_CSV,
    model_path: str = DEFAULT_MODEL_PATH,
) -> List[Tuple[str, int]]:
    """Predict a list of URLs; returns list of (url, label) pairs."""
    results = []
    pkg = _load_model_pkg(model_path)
    if pkg is None:
        log.info("No saved model found — training now…")
        train_model(train_csv, model_path)
        pkg = _load_model_pkg(model_path)

    model      = pkg["model"]
    train_cols = pkg["train_cols"]

    rows = [extract_features(u) for u in urls]
    df   = pd.DataFrame(rows)
    for col in train_cols:
        if col not in df.columns:
            df[col] = NF
    Xq     = df[train_cols].apply(pd.to_numeric, errors="coerce").fillna(NF)
    labels = model.predict(Xq)

    return list(zip(urls, [int(l) for l in labels]))


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self, train_csv: str, model_path: str, test_csv: str):
        super().__init__()
        self.train_csv  = train_csv
        self.model_path = model_path
        self.test_csv   = test_csv

        self.title("Malicious URL Detector")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")
        self.attributes("-alpha", 0.97)

        self._build_ui()

    # ------------------------------------------------------------------
    def _build_ui(self):
        PAD   = {"padx": 12, "pady": 8}
        BG    = "#1e1e2e"
        FG    = "#cdd6f4"
        ENTRY = "#313244"
        BTN   = "#89b4fa"
        BTN_FG = "#1e1e2e"

        header = tk.Label(
            self, text="🔍  Malicious URL Detector",
            font=("Helvetica", 18, "bold"),
            bg=BG, fg="#cba6f7",
        )
        header.pack(**PAD)

        # URL input row
        input_frame = tk.Frame(self, bg=BG)
        input_frame.pack(fill=tk.X, **PAD)

        tk.Label(input_frame, text="URL:", bg=BG, fg=FG, font=("Helvetica", 12)).pack(side=tk.LEFT)
        self.entry = tk.Entry(
            input_frame, bd=2, relief=tk.FLAT,
            font=("Courier", 11), bg=ENTRY, fg=FG,
            insertbackground=FG, width=80,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        self.entry.bind("<Return>", lambda _: self._on_submit())

        # Buttons
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(**PAD)

        for text, cmd in [
            ("Check URL",  self._on_submit),
            ("Clear",      self._on_clear),
            ("About",      self._on_about),
        ]:
            tk.Button(
                btn_frame, text=text, command=cmd,
                bg=BTN, fg=BTN_FG,
                activebackground="#74c7ec", relief=tk.FLAT,
                font=("Helvetica", 11, "bold"), padx=10,
            ).pack(side=tk.LEFT, padx=4)

        # Result label
        self.result_var = tk.StringVar(value="")
        self.result_lbl = tk.Label(
            self, textvariable=self.result_var,
            font=("Helvetica", 13, "bold"),
            bg=BG, fg=FG,
        )
        self.result_lbl.pack(**PAD)

        # History
        tk.Label(self, text="History", bg=BG, fg="#a6e3a1",
                 font=("Helvetica", 11, "bold")).pack(anchor="w", padx=12)
        self.history = scrolledtext.ScrolledText(
            self, height=10, state=tk.DISABLED,
            font=("Courier", 10), bg=ENTRY, fg=FG,
            relief=tk.FLAT, padx=6, pady=4,
        )
        self.history.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            self, textvariable=self.status_var,
            bg="#313244", fg="#a6adc8", anchor="w",
            font=("Helvetica", 9),
        ).pack(fill=tk.X, side=tk.BOTTOM)

    # ------------------------------------------------------------------
    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.update_idletasks()

    def _log_history(self, line: str):
        self.history.configure(state=tk.NORMAL)
        self.history.insert(tk.END, line + "\n")
        self.history.see(tk.END)
        self.history.configure(state=tk.DISABLED)

    def _on_clear(self):
        self.entry.delete(0, tk.END)
        self.result_var.set("")

    def _on_about(self):
        messagebox.showinfo(
            "About",
            "Malicious URL Detector — Improved Edition\n\n"
            "Features: RF classifier, Shannon entropy, URL shortener detection,\n"
            "suspicious TLD check, subdomain depth, Safe Browsing API (optional).\n\n"
            "Set SAFE_BROWSING_API_KEY env var to enable Google Safe Browsing.",
        )

    def _on_submit(self):
        url = self.entry.get().strip()
        if not url:
            messagebox.showwarning("Input needed", "Please enter a URL.")
            return

        self._set_status(f"Analysing: {url[:80]}…")
        self.configure(cursor="watch")
        self.update()

        try:
            label = predict_url(
                url,
                train_csv=self.train_csv,
                test_csv=self.test_csv,
                model_path=self.model_path,
            )
        except Exception as exc:
            log.exception("Prediction failed")
            messagebox.showerror("Error", f"Prediction failed:\n{exc}")
            self._set_status("Error")
            self.configure(cursor="")
            return
        finally:
            self.configure(cursor="")

        if label == 1:
            self.result_var.set("⚠️  MALICIOUS")
            self.result_lbl.configure(fg="#f38ba8")
            self._log_history(f"[MALICIOUS] {url}")
            ans = messagebox.askyesno(
                "Warning",
                f"⚠️ This URL looks MALICIOUS:\n{url}\n\nOpen it anyway?",
            )
            if ans:
                webbrowser.open(url)
        else:
            self.result_var.set("✅  SAFE")
            self.result_lbl.configure(fg="#a6e3a1")
            self._log_history(f"[SAFE]      {url}")
            ans = messagebox.askyesno("Safe", f"✅ URL looks SAFE:\n{url}\n\nOpen it?")
            if ans:
                webbrowser.open(url)

        self._set_status("Done")


def run_gui(train_csv: str, model_path: str, test_csv: str):
    app = App(train_csv, model_path, test_csv)
    app.mainloop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Malicious URL Detector — single-file improved edition",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--gui",        action="store_true",    help="Launch GUI (default if no other action)")
    parser.add_argument("--train",      action="store_true",    help="Train and save the RF model")
    parser.add_argument("--predict",    metavar="URL",          help="Predict a single URL")
    parser.add_argument("--batch",      metavar="FILE",         help="Predict URLs listed one-per-line in FILE")
    parser.add_argument("--train-csv",  default=DEFAULT_TRAIN_CSV,  metavar="CSV",  help="Training CSV")
    parser.add_argument("--model",      default=DEFAULT_MODEL_PATH, metavar="PATH", help="Model file path")
    parser.add_argument("--test-csv",   default=DEFAULT_TEST_CSV,   metavar="CSV",  help="Temp CSV for single prediction")
    parser.add_argument("--cv",         type=int, default=0,        metavar="K",    help="Cross-validation folds (0=off)")
    parser.add_argument("--n-estimators", type=int, default=200,    metavar="N",    help="RF estimators")
    parser.add_argument("--verbose",    action="store_true",    help="DEBUG logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # --- TRAIN ---
    if args.train:
        train_model(
            train_csv=args.train_csv,
            model_path=args.model,
            n_estimators=args.n_estimators,
            cv=args.cv,
        )
        print(f"Model saved → {args.model}")
        return

    # --- SINGLE PREDICT ---
    if args.predict:
        label = predict_url(
            args.predict,
            train_csv=args.train_csv,
            test_csv=args.test_csv,
            model_path=args.model,
        )
        verdict = "MALICIOUS" if label == 1 else "SAFE"
        print(f"{verdict}  {args.predict}")
        return

    # --- BATCH PREDICT ---
    if args.batch:
        if not os.path.exists(args.batch):
            sys.exit(f"File not found: {args.batch}")
        with open(args.batch, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        if not urls:
            sys.exit("No URLs found in file.")
        results = predict_batch(urls, train_csv=args.train_csv, model_path=args.model)
        for url, label in results:
            verdict = "MALICIOUS" if label == 1 else "SAFE"
            print(f"{verdict}\t{url}")
        return

    # --- GUI (default) ---
    run_gui(train_csv=args.train_csv, model_path=args.model, test_csv=args.test_csv)
