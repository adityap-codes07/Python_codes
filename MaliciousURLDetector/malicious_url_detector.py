from __future__ import annotations

import os
import re
import csv
import json
import argparse
import urllib.request
from urllib.parse import urlparse
from xml.dom import minidom
from typing import Dict, Any, Optional, List

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib  # pip install joblib

# GUI
from tkinter import Tk, Frame, Label, Entry, Button, LEFT, RIGHT, BOTTOM
import tkinter.messagebox as tkMessageBox
import webbrowser

try:
    import pygeoip  # pip install pygeoip
except Exception as e:
    pygeoip = None


# =========================
# Constants / Defaults
# =========================
NF = -1
DEFAULT_TRAIN_CSV = "url_features.csv"
DEFAULT_TEST_CSV = "test_features.csv"
DEFAULT_MODEL_PATH = "rf_model.joblib"

# Optional: set SAFE_BROWSING_API_KEY env var for real check
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()


# =========================
# Helpers
# =========================
def _safe_int(x, default=NF) -> int:
    try:
        if x is None:
            return default
        if isinstance(x, str) and x.strip() == "":
            return default
        return int(float(x))
    except Exception:
        return default


def _tokenise(text: str) -> List[float]:
    """
    Returns: [avg_token_len, token_count, largest_token_len]
    """
    if not text:
        return [0.0, 0.0, 0.0]
    parts = re.split(r"\W+", text)
    parts = [p for p in parts if p]
    if not parts:
        return [0.0, 0.0, 0.0]
    lengths = [len(p) for p in parts]
    return [sum(lengths) / len(lengths), float(len(parts)), float(max(lengths))]


def _security_sensitive(tokens: List[str]) -> int:
    sec_words = {"confirm", "account", "banking", "secure", "ebayisapi", "webscr", "login", "signin"}
    return sum(1 for t in tokens if t in sec_words)


def _has_exe(url: str) -> int:
    return 1 if ".exe" in url.lower() else 0


def _looks_like_ip(tokens: List[str]) -> int:
    """
    Detect 4 consecutive numeric tokens (rough IP).
    """
    cnt = 0
    for t in tokens:
        if t.isnumeric():
            cnt += 1
            if cnt >= 4:
                return 1
        else:
            cnt = 0
    return 0


def _find_ele_with_attribute(dom, ele: str, attribute: str):
    for subelement in dom.getElementsByTagName(ele):
        if subelement.hasAttribute(attribute):
            return subelement.attributes[attribute].value
    return NF


def _site_popularity_alexa(host: str) -> List[int]:
    """
    Original project used Alexa XML endpoint.
    This endpoint may fail; we return [-1, -1] on errors.
    """
    if not host:
        return [NF, NF]
    try:
        xml_url = "http://data.alexa.com/data?cli=10&dat=snbamz&url=" + host
        with urllib.request.urlopen(xml_url, timeout=7) as resp:
            dom = minidom.parse(resp)
        rank_host = _find_ele_with_attribute(dom, "REACH", "RANK")
        rank_country = _find_ele_with_attribute(dom, "COUNTRY", "RANK")
        return [_safe_int(rank_host), _safe_int(rank_country)]
    except Exception:
        return [NF, NF]


def _get_asn(host: str) -> int:
    """
    Needs GeoIPASNum.dat in the same folder (like the original approach).
    If missing/unavailable, returns -1.
    """
    if not host or pygeoip is None:
        return NF
    try:
        db_path = "GeoIPASNum.dat"
        if not os.path.exists(db_path):
            return NF
        g = pygeoip.GeoIP(db_path)
        org = g.org_by_name(host)
        if not org:
            return NF
        # e.g. "AS15169 Google LLC" -> 15169
        first = org.split()[0]
        if first.startswith("AS"):
            return _safe_int(first[2:])
        return NF
    except Exception:
        return NF


def _safe_browsing_check(url: str) -> int:
    """
    If SAFE_BROWSING_API_KEY not set, return -1 (keeps compatibility).
    If set, returns 1 if threat match else 0.
    """
    if not SAFE_BROWSING_API_KEY:
        return NF

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "malicious-url-detector", "clientVersion": "1.0"},
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
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8").strip()
        return 1 if "matches" in data else 0
    except Exception:
        return NF


# =========================
# Feature Extraction
# =========================
def extract_features(url: str) -> Dict[str, Any]:
    """
    Produces a feature row (dict). Designed to match the original project style
    while being stable and numeric-friendly.
    """
    url = (url or "").strip()
    parsed = urlparse(url)

    host = parsed.netloc
    path = parsed.path

    tokens = re.split(r"\W+", url.lower())
    tokens = [t for t in tokens if t]

    rank_host, rank_country = _site_popularity_alexa(host)

    avg_url_tok, url_tok_cnt, largest_url_tok = _tokenise(url)
    avg_dom_tok, dom_tok_cnt, largest_dom_tok = _tokenise(host)
    avg_path_tok, path_tok_cnt, largest_path_tok = _tokenise(path)

    row = {
        "URL": url,
        "rank_host": rank_host,
        "rank_country": rank_country,
        "host": host,
        "path": path,
        "Length_of_url": len(url),
        "Length_of_host": len(host),
        "No_of_dots": url.count("."),
        "avg_token_length": avg_url_tok,
        "token_count": url_tok_cnt,
        "largest_token": largest_url_tok,
        "avg_domain_token_length": avg_dom_tok,
        "domain_token_count": dom_tok_cnt,
        "largest_domain": largest_dom_tok,
        "avg_path_token": avg_path_tok,
        "path_token_count": path_tok_cnt,
        "largest_path": largest_path_tok,
        "sec_sen_word_cnt": _security_sensitive(tokens),
        "IPaddress_presence": _looks_like_ip(tokens),
        "exe_in_url": _has_exe(url),
        "ASNno": _get_asn(host),
        "safebrowsing": _safe_browsing_check(url),
    }
    return row


def write_single_row_csv(row: Dict[str, Any], out_csv: str) -> None:
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)


# =========================
# ML: Train / Load / Predict
# =========================
def _get_train_cols(df: pd.DataFrame) -> List[str]:
    # Exclude non-feature columns
    exclude = {"URL", "host", "path", "malicious", "result"}
    return [c for c in df.columns if c not in exclude]


def train_model(train_csv: str, model_path: str = DEFAULT_MODEL_PATH) -> RandomForestClassifier:
    if not os.path.exists(train_csv):
        raise FileNotFoundError(f"Training dataset not found: {train_csv}")

    train_df = pd.read_csv(train_csv)

    if "malicious" not in train_df.columns:
        raise ValueError("Training CSV must contain 'malicious' column (0/1 labels).")

    train_cols = _get_train_cols(train_df)

    # Convert everything feature-like to numeric
    X = train_df[train_cols].apply(pd.to_numeric, errors="coerce").fillna(NF)
    y = train_df["malicious"].apply(_safe_int)

    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X, y)

    joblib.dump({"model": model, "train_cols": train_cols}, model_path)
    return model


def load_model(model_path: str = DEFAULT_MODEL_PATH):
    if not os.path.exists(model_path):
        return None
    return joblib.load(model_path)


def predict_url(
    url: str,
    train_csv: str = DEFAULT_TRAIN_CSV,
    test_csv: str = DEFAULT_TEST_CSV,
    model_path: str = DEFAULT_MODEL_PATH,
) -> int:
    """
    Returns:
      0 => Safe
      1 => Malicious
    """
    row = extract_features(url)
    write_single_row_csv(row, test_csv)

    pack = load_model(model_path)
    if pack is None:
        # If no saved model, train once (same idea as repo needing the training CSV)
        train_model(train_csv, model_path)
        pack = load_model(model_path)

    model = pack["model"]
    train_cols = pack["train_cols"]

    test_df = pd.read_csv(test_csv)
    Xq = test_df[train_cols].apply(pd.to_numeric, errors="coerce").fillna(NF)

    pred = model.predict(Xq)[0]
    return int(pred)


# =========================
# GUI
# =========================
def run_gui(
    train_csv: str = DEFAULT_TRAIN_CSV,
    model_path: str = DEFAULT_MODEL_PATH,
    test_csv: str = DEFAULT_TEST_CSV,
):
    root = Tk()
    root.title("Malicious URL Detector (Improved)")
    root.attributes("-alpha", 0.95)

    frame = Frame(root)
    frame.pack()

    bottomframe = Frame(root)
    bottomframe.pack(side=BOTTOM)

    Label(frame, text="Enter the URL: ").pack(side=LEFT)
    entry = Entry(frame, bd=5, width=120)
    entry.pack(side=RIGHT)

    def about():
        tkMessageBox.showinfo(
            "About",
            "Single-file improved version of Malicious URL Detector.\n"
            "Keeps original pipeline: extract → CSV → RF predict → result.",
        )

    def submit():
        url = entry.get().strip()
        if not url:
            tkMessageBox.showwarning("Input needed", "Please enter a URL.")
            return

        try:
            label = predict_url(url, train_csv=train_csv, test_csv=test_csv, model_path=model_path)
        except Exception as e:
            tkMessageBox.showerror("Error", f"Prediction failed:\n{e}")
            return

        if label == 0:
            tkMessageBox.showinfo("Result", f"The URL is SAFE:\n{url}")
            ans = tkMessageBox.askquestion("Redirect", "Do you want to open it?")
            if ans == "yes":
                webbrowser.open(url, new=1)

        elif label == 1:
            tkMessageBox.showwarning("Result", f"The URL is MALICIOUS:\n{url}")
            ans2 = tkMessageBox.askquestion("Redirect", "This URL is malicious. Open anyway?")
            if ans2 == "yes":
                webbrowser.open(url, new=1)
        else:
            # Should not happen with binary model, but kept for compatibility
            tkMessageBox.showwarning("Result", f"Suspicious URL:\n{url}")

    Button(root, text="About", command=about).pack(side=RIGHT, padx=6, pady=6)
    Button(bottomframe, text="Submit", command=submit).pack(side=RIGHT, padx=8, pady=8)

    root.mainloop()


# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="Malicious URL Detector (single-file improved)")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    parser.add_argument("--train", action="store_true", help="Train and save RF model")
    parser.add_argument("--predict", type=str, help="Predict a single URL")
    parser.add_argument("--train-csv", type=str, default=DEFAULT_TRAIN_CSV, help="Training CSV path")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL_PATH, help="Model path")
    parser.add_argument("--test-csv", type=str, default=DEFAULT_TEST_CSV, help="Test CSV path (generated)")
    args = parser.parse_args()

    if args.train:
        train_model(args.train_csv, args.model)
        print(f"Model saved to: {args.model}")
        return

    if args.predict:
        label = predict_url(args.predict, train_csv=args.train_csv, test_csv=args.test_csv, model_path=args.model)
        print("SAFE" if label == 0 else "MALICIOUS")
        return

    # Default behavior: GUI (like the original repo usage)
    if args.gui or (not args.train and not args.predict):
        run_gui(train_csv=args.train_csv, model_path=args.model, test_csv=args.test_csv)


if __name__ == "__main__":
    main()