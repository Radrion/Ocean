import sqlite3
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss
import os
import json
import ollama

# storage hierarchy

def setup_database():
    """Set up the SQLite database with the required tables."""
    conn = sqlite3.connect('cyber_prompts.db')
    cursor = conn.cursor()

    #  hierarchy table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            parent_id INTEGER,
            FOREIGN KEY (parent_id) REFERENCES categories (id)
        )
    ''')
    
    # saved prompts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS valid_prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_text TEXT NOT NULL,
            category_id INTEGER,
            FOREIGN KEY (category_id) REFERENCES categories (id)
        )
    ''')
    
    conn.commit()
    return conn, cursor

conn, cursor = setup_database()

# categories
cursor.execute("INSERT OR IGNORE INTO categories (name, parent_id) VALUES (?, ?)", ("Network Security", None))
net_sec_id = cursor.lastrowid

cursor.execute("INSERT OR IGNORE INTO categories (name, parent_id) VALUES (?, ?)", ("SIEM", None))
siem_id = cursor.lastrowid

# subcategories
subcategories = [
    ("Port Scanning", net_sec_id),
    ("Firewall Configuration", net_sec_id),
    ("Log Analysis", siem_id),
    ("Alert Rules", siem_id)
]

cursor.executemany("INSERT OR IGNORE INTO categories (name, parent_id) VALUES (?, ?)", subcategories)
conn.commit()

def evaluate_and_store_prompt(user_prompt, conn, cursor):
    '''check if the prompt is cybersecurity-related and store it in the database if allowed
    user_prompt: the prompt to evaluate
    conn: SQLite connection object
    cursor: SQLite cursor object'''
    qwen_response = ask_qwen(user_prompt) 
    
    try:
        # 2. Parse Qwen's JSON output
        result = json.loads(qwen_response)
        
        # 3. Check the "is_cybersecurity" flag
        if result.get("is_cybersecurity") is True:
            category_name = result.get("category")
            
            # Look up the category ID in our SQLite database
            cursor.execute("SELECT id FROM categories WHERE name = ?", (category_name,))
            row = cursor.fetchone()
            
            if row:
                category_id = row[0]
                # The prompt passed! Save it to the database.
                cursor.execute(
                    "INSERT INTO valid_prompts (prompt_text, category_id) VALUES (?, ?)", 
                    (user_prompt, category_id)
                )
                conn.commit()
                print(f"Allowed: Saved under '{category_name}'")
            else:
                print("Blocked: Category recognized by Qwen is not in our allowed hierarchy.")
        
        else:
            # This handles your "block" scenario for out-of-context prompts
            print("Blocked: Not a cybersecurity prompt.")
            
    except json.JSONDecodeError:
        print("Error: Qwen did not return valid JSON.")

def ask_qwen(user_prompt):
    '''asks the local Qwen model to classify the prompt and return JSON
    user_prompt: the prompt to classify'''
    system_instruction = """
    You are a strict cybersecurity classification filter.
    Your task is to classify the user prompt into one of the following allowed categories:
    - Network Security (Subcategories: Port Scanning, Firewall Configuration)
    - SIEM (Subcategories: Log Analysis, Alert Rules)

    If the prompt is about cybersecurity and fits these topics, respond in this EXACT JSON format:
    {
      "is_cybersecurity": true,
      "category": "<Exact Subcategory Name>"
    }

    If the prompt is NOT about cybersecurity or doesn't fit these categories, respond in this EXACT JSON format:
    {
      "is_cybersecurity": false,
      "category": null
    }

    Output ONLY valid JSON. No explanations or extra text.
    """

    
    response = ollama.chat(
        model="qwen",  # or your exact model tag, e.g., "qwen:7b"
        format="json",     # Forces Ollama to enforce valid JSON output
        messages=[
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_prompt}
        ]
    )

    return response['message']['content']

# Database

DB_PATH = os.environ.get("RAG_DB_PATH", "hermes_rag.db")

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

    cur.execute("DROP TABLE IF EXISTS docs")
    cur.execute("DROP TABLE IF EXISTS docs_fts")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS docs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            embedding BLOB NOT NULL
        )
    """)

    cur.execute("""
        CREATE VIRTUAL TABLE docs_fts
        USING fts5(title, content, content='docs', content_rowid='id')
    """)

    conn.commit()
    conn.close()


# Embedding helpers


def embed_texts(model, texts):
    """
    Turn a list of texts into a list of float32 NumPy vectors.
    """
    vecs = []
    for t in texts:
        emb = model.encode(t)                     
        v = np.array(emb, dtype=np.float32)       
        vecs.append(v)
    return vecs

def bytes_to_vec(b):
    """
    Convert bytes (from SQLite BLOB) back into a float32 NumPy vector.
    """
    return np.frombuffer(b, dtype=np.float32)

# SQLite


def store_docs(titles, contents, vecs):
    """
    Insert documents and their embeddings into the docs table.
    """
    conn = get_conn()
    cur = conn.cursor()

    for title, content, vec in zip(titles, contents, vecs):
        
        cur.execute(
            "INSERT INTO docs (title, content, embedding) VALUES (?, ?, ?)",
            (title, content, vec.tobytes())       
        )

        doc_id = cur.lastrowid

        cur.execute(
            "INSERT INTO docs_fts (rowid, title, content) VALUES (?, ?, ?)",
            (doc_id, title, content)
        )

    conn.commit()
    conn.close()


# Build FAISS index from SQLite


def build_faiss_index():
    """
    Load all embeddings from SQLite and build a FAISS index for fast search.
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, embedding FROM docs")
    rows = cur.fetchall()

    if not rows:
        conn.close()
        return None, []

    vectors = []
    ids = []
    for row in rows:
        vec = bytes_to_vec(row["embedding"])
        vec = vec / np.linalg.norm(vec)          # normalize for cosine similarity
        vectors.append(vec)
        ids.append(row["id"])

    vectors_np = np.vstack(vectors).astype('float32')

    dim = vectors_np.shape[1]
    index = faiss.IndexFlatIP(dim)              

    index.add(vectors_np)

    conn.close()
    return index, ids

# Retrieve top‑k docs with FAISS


def retrieve_top_k(model, query, index, ids, k=3):
    """
    Given a query string, return the top‑k most similar docs using FAISS.
    """
    conn = get_conn()
    cur = conn.cursor()

    q_emb = model.encode(query)
    q_vec = np.array(q_emb, dtype=np.float32)
    q_vec = q_vec / np.linalg.norm(q_vec)        
    q_vec = q_vec.reshape(1, -1).astype('float32')

    scores, faiss_indices = index.search(q_vec, k)

    results = []
    for score, idx in zip(scores[0], faiss_indices[0]):
        doc_id = ids[idx]                       


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

    safe_query = '"' + query.replace('"', '""') + '"'

    cur.execute("""
        SELECT rowid AS id, title, content
        FROM docs_fts
        WHERE docs_fts MATCH ?
        LIMIT ?
    """, (safe_query, fts_limit))

    fts_rows = cur.fetchall()

    if not fts_rows:
        conn.close()
        return []

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

    dim = vectors_np.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(vectors_np)

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


# Main


def main():
    """
    Build the index, store docs, and run a sample query.
    """
    model = SentenceTransformer("all-MiniLM-L6-v2")

    init_db()

    titles = ["Doc 1", "Doc 2", "Doc 3"]
    contents = [
        "This is a sample text about cats and animals.",
        "This is another text about programming and Python.",
        "This document talks about databases, SQLite, and embeddings."
    ]

    vecs = embed_texts(model, contents)
    store_docs(titles, contents, vecs)

    query = "Python programming"
    top_docs = hybrid_retrieve(model, query, k=2, fts_limit=10)

    print("Hybrid top results:")
    for score, doc_id, title, content in top_docs:
        print(f"\nScore: {score:.4f}")
        print(f"ID: {doc_id}")
        print(f"Title: {title}")
        print(f"Content: {content}")

    index, ids = build_faiss_index()
    if index is None:
        print("No documents indexed.")
        return

    query = "Tell me something about Python and programming."
    top_docs = retrieve_top_k(model, query, index, ids, k=2)

    print("Top results:")
    for score, title, content in top_docs:
        print(f"\nScore: {score:.4f}")
        print(f"Title: {title}")
        print(f"Content: {content}")
if __name__ == "__main__":
    main() 
