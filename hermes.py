"""
hermes.py — Core pipeline: Wazuh auth, alert ingestion, NL-to-SQL, RAG cache.

This file only defines functions and module-level connections meant to be
imported by api.py. It does NOT run get_agents(), take input(), or query
anything at import time — that was moved into api.py's startup routine so
importing this file has no side effects (a bug in the previous version:
get_wazuh_token() was defined twice, silently discarding the retry logic).
"""

import os
import re
import time

import requests
import urllib3
import pandas as pd
import duckdb
import ollama
import matplotlib
matplotlib.use("Agg")  # no GUI backend needed — API returns data, not plots
import matplotlib.pyplot as plt

from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

from rag import init_db, store_docs, embed_texts, hybrid_retrieve

# base setup
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MANAGER_URL = os.environ.get("MANAGER_URL")
INDEXER_URL = os.environ.get("INDEXER_URL")
WAZUH_USERNAME = os.environ.get("WAZUH_USERNAME")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD")
INDEXER_USERNAME = os.environ.get("INDEXER_USERNAME")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5")

DANGEROUS = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'TRUNCATE']

_rag_model = None  # loaded once via get_rag_model()


def get_rag_model():
    """Lazily load the sentence-transformer model once and reuse it."""
    global _rag_model
    if _rag_model is None:
        _rag_model = SentenceTransformer("all-MiniLM-L6-v2")
        init_db()
    return _rag_model


# ── Wazuh Manager API ───────────────────────────────────────────────────

def get_wazuh_token(base_url, username, password, retries=5, delay=10):
    """Authenticate with the Wazuh manager API, retrying while Docker
    containers finish starting up."""
    for attempt in range(retries):
        try:
            response = requests.post(
                f"{base_url}/security/user/authenticate",
                auth=(username, password),
                verify=False
            )
            if response.status_code == 200:
                print("Authenticated successfully!")
                return response.json()['data']['token']
            else:
                print(f"Authentication failed: {response.json()}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"Wazuh not ready yet, retrying in {delay}s... ({attempt + 1}/{retries})")
            time.sleep(delay)
    print("Could not connect to Wazuh after multiple attempts.")
    return None


def get_agents(base_url, token):
    """Get the list of monitored machines (agents) from the Wazuh API."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{base_url}/agents", headers=headers, verify=False)
    return response.json()


# wazuh indexer

def get_alerts(base_url_indexer, username, password, limit=50):
    """Pull raw alert documents from the Wazuh indexer."""
    response = requests.get(
        f"{base_url_indexer}/wazuh-alerts*/_search",
        auth=(username, password),
        params={"size": limit},
        verify=False
    )
    if response.status_code != 200:
        print(f"Indexer request failed with status {response.status_code}")
        print("Raw response:", response.text[:500])
        return {"hits": {"hits": []}}
    try:
        return response.json()
    except ValueError:
        print("Indexer did not return valid JSON. Raw response:")
        print(response.text[:500])
        return {"hits": {"hits": []}}


def get_latest_alert(base_url_indexer, username, password):
    """
    Fetch the single most recent raw alert document, unflattened,
    for use in the alert analyzer UI (which needs the full nested
    structure — agent.ip, rule.mitre, data.win.eventdata, etc.)
    Returns None if no alerts exist yet.
    """
    response = requests.get(
        f"{base_url_indexer}/wazuh-alerts*/_search",
        auth=(username, password),
        params={"size": 1, "sort": "timestamp:desc"},
        verify=False
    )
    data = response.json()
    hits = data.get('hits', {}).get('hits', [])
    if not hits:
        return None
    return hits[0]['_source']


def process_alerts(alerts_response):
    """Flatten nested Wazuh alert JSON into a list of flat dictionaries."""
    processed_alerts = []
    for hit in alerts_response.get('hits', {}).get('hits', []):
        alert = hit.get('_source', {})
        processed_alerts.append({
            "timestamp": alert.get('timestamp'),
            "agent_name": alert.get('agent', {}).get('name'),
            "rule_level": alert.get('rule', {}).get('level'),
            "rule_description": alert.get('rule', {}).get('description'),
            "data": str(alert.get('data', {})),
        })
    return processed_alerts


# duckdb setup

def load_into_duckdb(processed_alerts):
    """Load processed alerts into an in-memory DuckDB table called threats."""
    if not processed_alerts:
        # Empty list -> pd.DataFrame([]) has no columns, which breaks
        # CREATE TABLE. Seed a zero-row frame with the expected schema instead.
        df = pd.DataFrame(columns=["timestamp", "agent_name", "rule_level", "rule_description", "data"])
    else:
        df = pd.DataFrame(processed_alerts)
    conn = duckdb.connect(database=':memory:')
    conn.execute("CREATE TABLE threats AS SELECT * FROM df")
    print(f"Loaded {len(df)} alerts into DuckDB successfully!")
    return conn


def refresh_threats(conn, base_url_indexer, username, password, limit=500):
    """Pull fresh alerts and replace the threats table in-place."""
    alerts = get_alerts(base_url_indexer, username, password, limit=limit)
    processed = process_alerts(alerts)
    if not processed:
        df = pd.DataFrame(columns=["timestamp", "agent_name", "rule_level", "rule_description", "data"])
    else:
        df = pd.DataFrame(processed)
    conn.execute("DROP TABLE IF EXISTS threats")
    conn.execute("CREATE TABLE threats AS SELECT * FROM df")
    return len(df)


def get_schema(conn):
    """Return the threats table schema (name + type only) as a string."""
    df = conn.execute("DESCRIBE threats").fetchdf()
    return df[['column_name', 'column_type']].to_string()


#sql translator

def load_soul(path="soul.md"):
    """Load the soul.md system prompt file."""
    with open(path, 'r') as f:
        return f.read()


def sql_translate(user_query, schema):
    """Ask the local LLM to translate an English question into SQL."""
    soul = load_soul()
    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {"role": "system", "content": f"{soul}\n\nCurrent table schema:\n{schema}"},
            {"role": "user", "content": user_query},
        ]
    )
    return response['message']['content']


def sql_cleaner(sql_query):
    """Strip markdown fences and explanation text from the LLM's output."""
    match = re.search(r'```sql\s*(.*?)\s*```', sql_query, re.DOTALL)
    if match:
        return match.group(1).strip()
    return sql_query.strip()


def run_query(conn, sql_query):
    """Execute the cleaned SQL, blocking anything destructive."""
    if any(word in sql_query.upper() for word in DANGEROUS):
        print("Blocked dangerous SQL:", sql_query)
        return None
    return conn.execute(sql_query).fetchdf()


#Visualization

def describe_result(df):
    """
    Decide how the frontend should render this result.
    Returns a dict the React app can use to pick a chart type,
    instead of rendering a matplotlib image server-side.
    """
    if df is None or df.empty:
        return {"type": "empty"}

    rows, cols = df.shape

    if rows == 1 and cols == 1:
        return {"type": "single_value", "value": df.iloc[0, 0]}

    if cols == 2 and pd.api.types.is_numeric_dtype(df.iloc[:, 1]):
        return {
            "type": "bar",
            "labels": df.iloc[:, 0].astype(str).tolist(),
            "values": df.iloc[:, 1].tolist(),
            "x_label": df.columns[0],
            "y_label": df.columns[1],
        }

    if "timestamp" in df.columns:
        return {
            "type": "line",
            "records": df.to_dict(orient="records"),
        }

    return {
        "type": "table",
        "columns": df.columns.tolist(),
        "records": df.to_dict(orient="records"),
    }

#Full engine with rag

def query_engine(user_question, dd_conn):
    """
    Check the RAG cache for a similar past query first; fall back to
    Qwen2.5 if nothing close enough is found. Returns (sql, dataframe).
    """
    rag_model = get_rag_model()
    similar = hybrid_retrieve(rag_model, user_question, k=1, fts_limit=10)

    if similar and similar[0][0] > 0.85:
        score, doc_id, title, content = similar[0]
        print(f"Found similar past query (score: {score:.2f}): {title}")
        sql_clean = content
    else:
        schema = get_schema(dd_conn)
        sql_raw = sql_translate(user_question, schema)
        sql_clean = sql_cleaner(sql_raw)

        vecs = embed_texts(rag_model, [sql_clean])
        store_docs(titles=[user_question], contents=[sql_clean], vecs=vecs)
        print("New query stored in RAG")

    result = run_query(dd_conn, sql_clean)
    return sql_clean, result