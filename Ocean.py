import os
import re
import time
import numpy as np
import requests
import urllib3
import pandas as pd
import duckdb
import ollama
import anthropic
import openai
import datetime as _dt
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from rag import init_db, store_docs, embed_texts, hybrid_retrieve
import plotly.graph_objects as go
import plotly.express as px

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MANAGER_URL = os.environ.get("MANAGER_URL")
INDEXER_URL = os.environ.get("INDEXER_URL")
WAZUH_USERNAME = os.environ.get("WAZUH_USERNAME")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD")
INDEXER_USERNAME = os.environ.get("INDEXER_USERNAME")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen")

DANGEROUS = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'TRUNCATE']

rag_model = None  


def get_rag_model():
    """Lazily load the sentence-transformer model once and reuse it."""
    global rag_model
    if rag_model is None:
        rag_model = SentenceTransformer("all-MiniLM-L6-v2")
        init_db()
    return rag_model


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
    """Return the single most recent raw alert (full nested JSON) for the Alert Analyzer component's 'Fetch Live Alert' button.
    base_url_indexer: the Wazuh Indexer API base URL
    username, password: credentials for the Indexer API
    """
    response = requests.get(
        f"{base_url_indexer}/wazuh-alerts*/_search",
        auth=(username, password),
        params={"size": 1, "sort": "timestamp:desc"},
        verify=False
    )
    if response.status_code != 200:
        print(f"Indexer request failed with status {response.status_code}")
        print("Raw response:", response.text[:500])
        return None
    try:
        data = response.json()
    except ValueError:
        print("Indexer did not return valid JSON. Raw response:")
        print(response.text[:500])
        return None
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
    df = _empty_threats_df() if not processed_alerts else pd.DataFrame(processed_alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    conn = duckdb.connect(database=':memory:')
    conn.execute("CREATE TABLE threats AS SELECT * FROM df")
    print(f"Loaded {len(df)} alerts into DuckDB successfully!")
    return conn


def refresh_threats(conn, base_url_indexer, username, password, limit=500):
    """Refresh the DuckDB database with the latest alerts from Wazuh.
    conn: a DuckDB connection object
    base_url_indexer: the Wazuh Indexer API base URL
    username, password: credentials for the Indexer API
    limit: how many alerts to fetch (default 500)"""
    alerts = get_alerts(base_url_indexer, username, password, limit=limit)
    processed = process_alerts(alerts)
    df = _empty_threats_df() if not processed else pd.DataFrame(processed)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    conn.execute("DROP TABLE IF EXISTS threats")
    conn.execute("CREATE TABLE threats AS SELECT * FROM df")
    return len(df)


def get_schema(conn):
    """Return the threats table schema as a string.
    conn: a DuckDB connection object"""
    df = conn.execute("DESCRIBE threats").fetchdf()
    return df[['column_name', 'column_type']].to_string()


# natural language to SQL

def load_soul(path="soul.md"):
    """Load the soul.md system prompt file."""
    with open(path, 'r') as f:
        return f.read()


llm_config = {
    "provider": "ollama",
    "model": OLLAMA_MODEL,
    "api_key": None,
}

def set_llm_config(provider, model, api_key=None):
    """Set the LLM provider and model to use for SQL translation and summarization.
    provider: desired LLM provider ("ollama", "anthropic", or "openai")
    model: the model name to use for the selected provider
    api_key: optional API key for providers that require it (Anthropic, OpenAI)"""
    llm_config["provider"] = provider
    llm_config["model"] = model
    llm_config["api_key"] = api_key


def ask_llm(messages):
    """Route a chat completion request to whichever provider is currently
    selected.
    messages: a list of dicts with 'role' and 'content' keys, e.g.:"""
    provider = llm_config["provider"]
    model = llm_config["model"]

    if provider == "ollama":
        response = ollama.chat(model=model, messages=messages, keep_alive="30m")
        return response['message']['content'].strip()

    if provider == "anthropic":
        client = anthropic.Anthropic(api_key=llm_config["api_key"])
        system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msgs = [m for m in messages if m["role"] != "system"]
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_msg,
            messages=user_msgs,
        )
        return response.content[0].text.strip()

    if provider == "openai":
        client = openai.OpenAI(api_key=llm_config["api_key"])
        response = client.chat.completions.create(model=model, messages=messages)
        return response.choices[0].message.content.strip()

    raise ValueError(f"Unknown LLM provider: {provider}")


def build_system_prompt(schema, retry=False):
    """Builds the full system prompt for SQL generation, including the
    time/severity vocab and the retry-strengthening text when needed."""
    soul = load_soul()
    now_utc = pd.Timestamp.now(tz="UTC")

    time_context = (
        f"The current date and time is: {now_utc.isoformat()} (UTC).\n"
        f"When the user mentions a relative time period, translate it using this exact reference point:\n"
        f"- \"today\" -> timestamp >= TIMESTAMP '{now_utc.normalize().isoformat()}'\n"
        f"- \"past 24 hours\" / \"last day\" -> timestamp >= TIMESTAMP '{(now_utc - pd.Timedelta(hours=24)).isoformat()}'\n"
        f"- \"past week\" / \"last 7 days\" -> timestamp >= TIMESTAMP '{(now_utc - pd.Timedelta(days=7)).isoformat()}'\n"
        f"- \"past month\" / \"last 30 days\" -> timestamp >= TIMESTAMP '{(now_utc - pd.Timedelta(days=30)).isoformat()}'\n"
        f"Always use an explicit TIMESTAMP '...' literal — never NOW() or CURRENT_TIMESTAMP."
    )

    severity_context = (
        "Wazuh's rule_level ranges from 0-15. Translate vague severity words:\n"
        "- \"critical\", \"dangerous\", \"severe\", \"high-risk\" -> rule_level >= 12\n"
        "- \"high\", \"serious\", \"significant\" -> rule_level >= 9\n"
        "- \"suspicious\", \"concerning\", \"medium\", \"moderate\", \"interesting\" -> rule_level >= 7\n"
        "- \"low\", \"minor\", \"low-risk\" -> rule_level BETWEEN 3 AND 6\n"
        "- \"benign\", \"informational\", \"normal\" -> rule_level < 3\n"
        "Never search these as text with LIKE — always use a rule_level condition."
    )

    examples = (
        "EXAMPLES of correctly handling requests, including ones that mention charts/trends/visuals:\n\n"
        "Q: Show me a visual trend of threat levels this past week\n"
        "A: SELECT timestamp, rule_level FROM threats WHERE timestamp >= TIMESTAMP '2026-01-01T00:00:00+00:00' - INTERVAL '7 DAYS' ORDER BY timestamp;\n\n"
        "Q: Show me today's alerts\n"
        "A: SELECT * FROM threats WHERE timestamp >= TIMESTAMP '2026-01-01T00:00:00+00:00' ORDER BY timestamp DESC;\n\n"
        "Q: Give me a chart of alerts by agent\n"
        "A: SELECT agent_name, COUNT(*) AS alert_count FROM threats GROUP BY agent_name ORDER BY alert_count DESC;\n\n"
        "Q: Show me 1 wazuh level under 5 from today\n"
        "A: SELECT * FROM threats WHERE rule_level < 5 AND timestamp >= TIMESTAMP '2026-01-01T00:00:00+00:00' LIMIT 1;\n\n"
        "Notice every answer above is ONLY a SQL query — no words like 'Sure', 'Here', or explanations.\n"
        "Q: Generate a chart showing threat levels from the past month\n"
        "A: SELECT timestamp, rule_level FROM threats WHERE timestamp >= TIMESTAMP '2026-01-01T00:00:00+00:00' - INTERVAL '1 MONTH' ORDER BY timestamp;\n\n"
    )

    rules = (
        f"{severity_context}\n\n"
        f"The table you must query is named exactly: threats\n"
        f"Do not use any other table name (e.g. 'alerts') — the table is called 'threats'.\n\n"
        f"{examples}\n"
        f"IMPORTANT: Even if asked for a 'chart', 'graph', 'trend', or 'visual', respond with "
        f"ONLY a SQL query — charts are generated automatically from your query's results.\n\n"
        f"Current table schema (columns in 'threats'):\n{schema}"
        f"{time_context}\n\n"
    )

    if retry:
        rules = (
            "Your previous response was NOT valid SQL. This is a strict retry.\n"
            "Respond with NOTHING except a single SQL SELECT statement.\n\n"
        ) + rules

    return f"{soul}\n\n{rules}"


def sql_translate(user_query, schema, retry=False):
    """Ask the local LLM to translate an English question into SQL."""
    system_content = build_system_prompt(schema, retry=retry)
    return ask_llm([
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_query},
    ])


def sql_cleaner(sql_query):
    """Clean the SQL generated by the LLM 
    sql_query: the raw SQL string returned by the LLM"""
    match = re.search(r'```sql\s*(.*?)\s*```', sql_query, re.DOTALL)
    cleaned = match.group(1).strip() if match else sql_query.strip()

    if not match:
        select_match = re.search(r'(?i)\bSELECT\b.*', cleaned, re.DOTALL)
        if select_match:
            cleaned = select_match.group(0).strip()

    cleaned = re.sub(r'(?i)\bFROM\s+\w+', 'FROM threats', cleaned)
    cleaned = re.sub(r'(?i)\bJOIN\s+\w+', 'JOIN threats', cleaned)

    now_literal = f"TIMESTAMP '{pd.Timestamp.now(tz='UTC').isoformat()}'"
    cleaned = re.sub(r'(?i)\bNOW\(\)', now_literal, cleaned)
    cleaned = re.sub(r'(?i)\bCURRENT_TIMESTAMP\b', now_literal, cleaned)

    cleaned = re.sub(
        r"(?<!TIMESTAMP )(?<!TIMESTAMP)'(\d{4}-\d{2}-\d{2}T[\d:.]+(?:\+\d{2}:?\d{2}|Z)?)'(\s*-\s*INTERVAL)",
        r"TIMESTAMP '\1'\2",
        cleaned
    )

    cleaned = re.sub(
        r"strftime\(\s*('[^']+')\s*,\s*(timestamp)\s*\)",
        r"strftime(\2, \1)",
        cleaned,
        flags=re.IGNORECASE
    )

    if ";" in cleaned:
        cleaned = cleaned.split(";")[0].strip() + ";"

    if not re.match(r'(?i)^\s*SELECT\b', cleaned):
        raise ValueError("Model response was not a valid SQL query")

    return cleaned

def summarize(user_question, sql_query, result_df, was_fallback=False):
    """Generate a short, conversational summary of query results.
    user_question: the original natural language question
    sql_query: the SQL that was run
    result_df: a pandas DataFrame containing the query results
    was_fallback: a boolean indicating whether the query was a fallback"""
    if result_df is None or result_df.empty:
        return "I didn't find any matching results for that."

    preview = result_df.head(5).to_dict(orient="records")
    fallback_note = (
        "Note: I couldn't confidently translate that exact question into a query, "
        "so here are the 10 most recent alerts instead. " if was_fallback else ""
    )
    prompt = (
        f"{fallback_note}A user asked: \"{user_question}\"\n\n"
        f"The following SQL was run: {sql_query}\n\n"
        f"It returned {len(result_df)} row(s). Preview:\n{preview}\n\n"
        f"Write a brief, natural 1-3 sentence summary for a security analyst. "
        f"Reference specific values where useful. Do not mention SQL or databases."
    )
    return ask_llm([{"role": "user", "content": prompt}])

def _empty_threats_df():
    """Return an empty DataFrame with the correct threats table schema."""
    df = pd.DataFrame(columns=["timestamp", "agent_name", "rule_level", "rule_description", "data"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df

def run_query(conn, sql_query):
    """Execute the cleaned SQL, blocking anything destructive.
    conn: a DuckDB connection object
    sql_query: a string containing the SQL to run"""
    if any(word in sql_query.upper() for word in DANGEROUS):
        print("Blocked dangerous SQL:", sql_query)
        return None
    return conn.execute(sql_query).fetchdf()


#  Autovisualization

def build_chart(df, chart_type, **kwargs):
    """Build a Plotly figure and return it as a JSON-serializable dict
    for the frontend to render with Plotly.js."""
    if chart_type == "bar":
        fig = px.bar(df, x=kwargs["x"], y=kwargs["y"],
                     labels={kwargs["x"]: kwargs["x"], kwargs["y"]: kwargs["y"]})
    elif chart_type == "line":
        fig = px.line(df, x="timestamp", y=kwargs["y"], markers=True)
    elif chart_type == "histogram":
        fig = px.histogram(df, x=kwargs["column"], nbins=10)
    else:
        return None

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#1e1e1e",
        font=dict(family="Consolas, monospace", color="#d4d4d4"),
        margin=dict(l=40, r=20, t=30, b=40),
    )
    return json_safe(fig.to_dict())

def json_safe(obj):
    """Recursively convert a value/dict/list into something jsonify can
    actually serialize 
    obj: the value to convert (can be a dict, list, or scalar)
    """
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_safe(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return [json_safe(v) for v in obj.tolist()]

    if obj is None:
        return None
    if obj is pd.NA:
        return None
    if isinstance(obj, (pd.Timestamp, _dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        val = float(obj)
        return None if (val != val or val in (float("inf"), float("-inf"))) else val
    if isinstance(obj, float) and obj != obj:
        return None
    try:
        if pd.isna(obj):
            return None
    except (TypeError, ValueError):
        pass

    return obj

def describe_result(df):
    """
    Decide how the frontend should render charts
    df: a pandas DataFrame containing the query result
    """
    if df is None or df.empty:
        return {"type": "empty"}

    rows, cols = df.shape

    if rows == 1 and cols == 1:
        return json_safe({"type": "single_value", "value": df.iloc[0, 0]})

    # line chart
    if "timestamp" in df.columns:
        numeric_cols = [c for c in df.columns if c != "timestamp" and pd.api.types.is_numeric_dtype(df[c])]
        if numeric_cols:
            sorted_df = df.sort_values("timestamp")
            y_col = numeric_cols[0]
            return json_safe({
                "type": "line",
                "labels": sorted_df["timestamp"].astype(str).tolist(),
                "values": sorted_df[y_col].tolist(),
                "y_label": y_col,
                "plotly": build_chart(sorted_df, "line", y=y_col),
            })

    #  histogram (distribution)
    if cols == 1 and rows > 1 and pd.api.types.is_numeric_dtype(df.iloc[:, 0]):
        values = df.iloc[:, 0].dropna().tolist()
        counts, bin_edges = np.histogram(values, bins=min(10, max(1, rows)))
        return json_safe({
            "type": "histogram",
            "bin_edges": [round(float(b), 2) for b in bin_edges],
            "counts": [int(c) for c in counts],
            "column": df.columns[0],
            "plotly": build_chart(df, "histogram", column=df.columns[0]),
        })

    #  bar chart
    if cols == 2 and pd.api.types.is_numeric_dtype(df.iloc[:, 1]):
        return json_safe({
            "type": "bar",
            "labels": df.iloc[:, 0].astype(str).tolist(),
            "values": df.iloc[:, 1].tolist(),
            "x_label": df.columns[0],
            "y_label": df.columns[1],
            "plotly": build_chart(df, "bar", x=df.columns[0], y=df.columns[1]),
        })

    return json_safe({
        "type": "table",
        "columns": df.columns.tolist(),
        "records": df.to_dict(orient="records"),
    })

    
# full engine

def query_engine(user_question, dd_conn):
    """Check the RAG cache for a similar past query first; fall back to
    Qwen if nothing close enough is found. Returns (sql, dataframe).
    user_question: a string containing the natural language question
    dd_conn: a DuckDB connection object"""
    rag_model = get_rag_model()
    similar = hybrid_retrieve(rag_model, user_question, k=1, fts_limit=10)

    if similar and similar[0][0] > 0.85:
        score, doc_id, title, content = similar[0]
        print(f"Found similar past query (score: {score:.2f}): {title}")
        sql_clean = content
    else:
        schema = get_schema(dd_conn)
        try:
            sql_raw = sql_translate(user_question, schema)
            sql_clean = sql_cleaner(sql_raw)
        except ValueError:
            print("First attempt wasn't valid SQL — retrying with a stricter prompt...")
            sql_raw = sql_translate(user_question, schema, retry=True)
            sql_clean = sql_cleaner(sql_raw)  # let this raise if it fails again

        vecs = embed_texts(rag_model, [sql_clean])
        store_docs(titles=[user_question], contents=[sql_clean], vecs=vecs)
        print("New query stored in RAG")

    result = run_query(dd_conn, sql_clean)
    summary = summarize(user_question, sql_clean, result)
    return sql_clean, result, summary