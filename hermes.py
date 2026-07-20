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

# ── Setup ────────────────────────────────────────────────────────────────
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


# wazuh token

def get_wazuh_token(base_url, username, password, retries=5, delay=10):
    """Authenticate with the Wazuh manager API, retrying while Docker
    containers finish starting up.
    base_url: the Wazuh Manager API base URL
    username, password: credentials for the Wazuh Manager API
    retries: how many times to retry if the API is not ready
    delay: seconds to wait between retries"""
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
    """Get the list of monitored machines (agents) from the Wazuh API.
    base_url: the Wazuh Manager API base URL
    token: the Bearer token obtained from get_wazuh_token()"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{base_url}/agents", headers=headers, verify=False)
    return response.json()


# Wazuh Indexer API 

def get_alerts(base_url_indexer, username, password, limit=50):
    """Pull raw alert documents from the Wazuh indexer.
    base_url_indexer: the Wazuh Indexer API base URL
    username, password: credentials for the Indexer API
    limit: how many alerts to fetch (default 50)"""
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
    base_url_indexer: the Wazuh Indexer API base URL
    username, password: credentials for the Indexer API"""
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
    """Flatten nested Wazuh alert JSON into a list of flat dictionaries.
    alerts_response: the raw JSON from get_alerts()"""
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


# ─duckdb

def load_into_duckdb(processed_alerts):
    """Load processed alerts into an in-memory DuckDB table called threats.
    processed_alerts: a list of flat dictionaries representing alerts"""
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
    """Pull fresh alerts and replace the threats table in-place.
    conn: a DuckDB connection object
    base_url_indexer: the Wazuh Indexer API base URL
    username, password: credentials for the Indexer API
    limit: how many alerts to fetch (default 500)"""
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
    """Return the threats table schema (name + type only) as a string.
    conn: a DuckDB connection object"""
    df = conn.execute("DESCRIBE threats").fetchdf()
    return df[['column_name', 'column_type']].to_string()


# natural language to SQL

def load_soul(path="soul.md"):
    """Load the soul.md system prompt file."""
    with open(path, 'r') as f:
        return f.read()


def sql_translate(user_query, schema):
    """Ask the local LLM to translate an English question into SQL.
    user_query: a string containing the natural language question
    schema: a string describing the table schema (columns + types)"""
    soul = load_soul()
    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    f"{soul}\n\n"
                    f"The table you must query is named exactly: threats\n"
                    f"Do not use any other table name (e.g. 'alerts') — the table is called 'threats'.\n\n"
                    f"Current table schema (columns in 'threats'):\n{schema}"
                ),
            },
            {"role": "user", "content": user_query},
        ]
    )
    return response['message']['content']


def sql_cleaner(sql_query):
    """Strip markdown fences and explanation text from the LLM's output,
    then force-correct the table name — small local models don't reliably
    follow the 'use table threats' instruction in the prompt, so this
    rewrites whatever table name they hallucinate back to the real one."""
    match = re.search(r'```sql\s*(.*?)\s*```', sql_query, re.DOTALL)
    cleaned = match.group(1).strip() if match else sql_query.strip()

    # Replace "FROM <anything>" / "JOIN <anything>" with the real table name.
    # This assumes a single-table query, which matches this project's schema.
    cleaned = re.sub(r'(?i)\bFROM\s+\w+', 'FROM threats', cleaned)
    cleaned = re.sub(r'(?i)\bJOIN\s+\w+', 'JOIN threats', cleaned)

    return cleaned


def run_query(conn, sql_query):
    """Execute the cleaned SQL, blocking anything destructive.
    conn: a DuckDB connection object
    sql_query: a string containing the SQL to run"""
    if any(word in sql_query.upper() for word in DANGEROUS):
        print("Blocked dangerous SQL:", sql_query)
        return None
    return conn.execute(sql_query).fetchdf()


# ── Autovisualization (returns a JSON-friendly description, not a plot) ──

def describe_result(df):
    """
    Decide how the frontend should render this result.
    Returns a dict the React app can use to pick a chart type,
    instead of rendering a matplotlib image server-side.
    df: a pandas DataFrame containing the SQL query result"""
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


# full engine

def query_engine(user_question, dd_conn):
    """
    Check the RAG cache for a similar past query first; fall back to
    Qwen2.5 if nothing close enough is found. Returns (sql, dataframe).
    user_question: a string containing the natural language question
    dd_conn: a DuckDB connection object
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