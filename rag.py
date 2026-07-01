import sqlite3
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss

DB_PATH = "rab.sqlite3"

# -----------------------------
# 1. Database helpers
# -----------------------------

def get_conn():
    """
    Open a connection to the SQLite database.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn

def init_db():
    """
    Create a fresh docs table to store text + embeddings.
    """
    conn = get_conn()
    cur = conn.cursor()

    # Drop old table if it exists
    cur.execute("DROP TABLE IF EXISTS docs")
    cur.execute("DROP TABLE IF EXISTS docs_fts")


    # Create new table with an embedding BLOB column
    cur.execute("""
        CREATE TABLE IF NOT EXISTS docs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            embedding BLOB NOT NULL
        )
    """)

    # FTS virtual table: stores text for keyword search
    cur.execute("""
        CREATE VIRTUAL TABLE docs_fts
        USING fts5(title, content, content='docs', content_rowid='id')
    """)

    conn.commit()
    conn.close()


# 2. Embedding helpers


def embed_texts(model, texts):
    """
    Turn a list of texts into a list of float32 NumPy vectors.
    """
    vecs = []
    for t in texts:
        emb = model.encode(t)                     # get embedding from model
        v = np.array(emb, dtype=np.float32)       # convert to float32 array
        vecs.append(v)
    return vecs

def bytes_to_vec(b):
    """
    Convert bytes (from SQLite BLOB) back into a float32 NumPy vector.
    """
    return np.frombuffer(b, dtype=np.float32)

# -----------------------------
# 3. Store docs in SQLite
# -----------------------------

def store_docs(titles, contents, vecs):
    """
    Insert documents and their embeddings into the docs table.
    """
    conn = get_conn()
    cur = conn.cursor()

    for title, content, vec in zip(titles, contents, vecs):
        # Insert into docs table
        cur.execute(
            "INSERT INTO docs (title, content, embedding) VALUES (?, ?, ?)",
            (title, content, vec.tobytes())       # store vector as bytes (BLOB)
        )

        doc_id = cur.lastrowid

        # Insert into FTS table, linked by rowid
        cur.execute(
            "INSERT INTO docs_fts (rowid, title, content) VALUES (?, ?, ?)",
            (doc_id, title, content)
        )

    conn.commit()
    conn.close()


# 4. Build FAISS index from SQLite


def build_faiss_index():
    """
    Load all embeddings from SQLite and build a FAISS index for fast search.
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, embedding FROM docs")
    rows = cur.fetchall()

    # If no rows, return empty index
    if not rows:
        conn.close()
        return None, []

    # Convert all embeddings from bytes to normalized float32 vectors
    vectors = []
    ids = []
    for row in rows:
        vec = bytes_to_vec(row["embedding"])
        vec = vec / np.linalg.norm(vec)          # normalize for cosine similarity
        vectors.append(vec)
        ids.append(row["id"])

    # Stack into a 2D NumPy array: shape (num_docs, dim)
    vectors_np = np.vstack(vectors).astype('float32')

    # Create a FAISS index that uses inner product (IP) as similarity
    dim = vectors_np.shape[1]
    index = faiss.IndexFlatIP(dim)               # IP + normalized vectors ≈ cosine

    # Add all document vectors to the index
    index.add(vectors_np)

    conn.close()
    return index, ids

# 5. Retrieve top‑k docs with FAISS


def retrieve_top_k(model, query, index, ids, k=3):
    """
    Given a query string, return the top‑k most similar docs using FAISS.
    """
    conn = get_conn()
    cur = conn.cursor()

    # Embed the query
    q_emb = model.encode(query)
    q_vec = np.array(q_emb, dtype=np.float32)
    q_vec = q_vec / np.linalg.norm(q_vec)        # normalize for cosine‑like similarity
    q_vec = q_vec.reshape(1, -1).astype('float32')

    # Search FAISS index: returns scores and indices into our vectors list
    scores, faiss_indices = index.search(q_vec, k)

    results = []
    for score, idx in zip(scores[0], faiss_indices[0]):
        doc_id = ids[idx]                        # map FAISS index back to SQLite id

        # Load full doc from SQLite
        cur.execute("SELECT title, content FROM docs WHERE id = ?", (doc_id,))
        row = cur.fetchone()

        results.append((float(score), row["title"], row["content"]))

    conn.close()
    return results

def hybrid_retrieve(model, query, k=3, fts_limit=20):
    """
    Hybrid retrieval:
    1) Use FTS to get keyword‑relevant docs.
    2) Use FAISS to rank them by semantic similarity.
    """
    conn = get_conn()
    cur = conn.cursor()

    # 1) FTS keyword search
    cur.execute("""
        SELECT rowid AS id, title, content
        FROM docs_fts
        WHERE docs_fts MATCH ?
        LIMIT ?
    """, (query, fts_limit))

    fts_rows = cur.fetchall()

    if not fts_rows:
        conn.close()
        return []

    # 2) Load embeddings for those FTS‑matched docs
    vectors = []
    ids = []
    titles = []
    contents = []

    for row in fts_rows:
        doc_id = row["id"]
        titles.append(row["title"])
        contents.append(row["content"])
        ids.append(doc_id)

        cur.execute("SELECT embedding FROM docs WHERE id = ?", (doc_id,))
        emb_row = cur.fetchone()
        vec = bytes_to_vec(emb_row["embedding"])
        vec = vec / np.linalg.norm(vec)
        vectors.append(vec)

    vectors_np = np.vstack(vectors).astype('float32')

    # 3) Build FAISS index over these candidate docs
    dim = vectors_np.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(vectors_np)

    # 4) Embed query and search FAISS
    q_emb = model.encode(query)
    q_vec = np.array(q_emb, dtype=np.float32)
    q_vec = q_vec / np.linalg.norm(q_vec)
    q_vec = q_vec.reshape(1, -1).astype('float32')

    scores, faiss_indices = index.search(q_vec, min(k, len(ids)))

    results = []
    for score, idx in zip(scores[0], faiss_indices[0]):
        doc_id = ids[idx]
        title = titles[idx]
        content = contents[idx]
        results.append((float(score), doc_id, title, content))

    conn.close()
    return results


# 6. Main: put it all together


def main():
    """
    Build the index, store docs, and run a sample query.
    """
    # Load embedding model
    model = SentenceTransformer("all-MiniLM-L6-v2")

    # 1) Initialize DB and index some sample docs
    init_db()

    titles = ["Doc 1", "Doc 2", "Doc 3"]
    contents = [
        "This is a sample text about cats and animals.",
        "This is another text about programming and Python.",
        "This document talks about databases, SQLite, and embeddings."
    ]

    vecs = embed_texts(model, contents)
    store_docs(titles, contents, vecs)

    #fts and faiss retrieval
    query = "Python programming"
    top_docs = hybrid_retrieve(model, query, k=2, fts_limit=10)

    print("Hybrid top results:")
    for score, doc_id, title, content in top_docs:
        print(f"\nScore: {score:.4f}")
        print(f"ID: {doc_id}")
        print(f"Title: {title}")
        print(f"Content: {content}")

    # 2) Build FAISS index from stored embeddings
    index, ids = build_faiss_index()
    if index is None:
        print("No documents indexed.")
        return

    # 3) Run a query
    query = "Tell me something about Python and programming."
    top_docs = retrieve_top_k(model, query, index, ids, k=2)

    print("Top results:")
    for score, title, content in top_docs:
        print(f"\nScore: {score:.4f}")
        print(f"Title: {title}")
        print(f"Content: {content}")

main() 
