import numpy as np
from langchain_huggingface import HuggingFaceEmbeddings
from sklearn.metrics.pairwise import cosine_similarity
import re
import pickle

embedder = HuggingFaceEmbeddings(model_name='sentence-transformers/all-MiniLM-L6-v2')

def clean_text(text):
    #Preprocess text by lowercasing and removing unwanted characters.
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s.,]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def create_embeddings(documents):
    #Generating embeddings for a list of documents.
    cleaned_docs = [clean_text(doc) for doc in documents]
    return embedder.embed_documents(cleaned_docs)


def search_similar(query, documents, embeddings, top_n=2):
    #Find the top N most similar documents to a given query.
    query_vec = [embedder.embed_query(clean_text(query))]
    scores = cosine_similarity(query_vec, embeddings)[0]

    # Get the top N indices
    top_indices = np.argsort(scores)[::-1][:top_n]
    print("\nTop Similar Documents:\n")
    for i, idx in enumerate(top_indices):
        print(f"{i+1}. Score: {scores[idx]:.4f}")
        print(f"   {documents[idx][:250]}...")  # printing the first 250 chars
        print("-" * 80)


def save_embeddings(filename, documents, embeddings):
    with open(filename, "wb") as f:
        pickle.dump((documents, embeddings), f)
    print(f"✅ Embeddings saved to {filename}")


def load_embeddings(filename):
    try:
        with open(filename, "rb") as f:
            docs, vecs = pickle.load(f)
        print(f"✅ Loaded {len(docs)} documents from {filename}")
        return docs, vecs
    except FileNotFoundError:
        print("⚠️ No saved embeddings found.")
        return [], []


def main():
    docs, vec_space = load_embeddings("doc_embeddings.pkl")
    if not docs:
        docs = [
            "Newton's Laws of Motion describe the relationship between motion and forces...",
            "The Indus Valley Civilization was one of the world's earliest urban civilizations...",
            "Quantum computing uses qubits and superposition for faster computation...",
            "The Indian Army is responsible for the defense and national security of India...",
            "The Parachute Regiment is an elite airborne and special operations force..."
        ]
        vec_space = create_embeddings(docs)
        save_embeddings("doc_embeddings.pkl", docs, vec_space)

    while True:
        print("\nOptions: \n1. Search \n2. Add new document \n3. Save & Exit")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            query = input("Enter your query: ")
            search_similar(query, docs, vec_space, top_n=3)

        elif choice == '2':
            new_doc = input("Enter the new document text: ")
            docs.append(new_doc)
            new_vec = embedder.embed_documents([clean_text(new_doc)])
            vec_space = np.vstack([vec_space, new_vec])
            print("✅ Document added and embedded.")

        elif choice == '3':
            save_embeddings("doc_embeddings.pkl", docs, vec_space)
            print("👋 Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")
