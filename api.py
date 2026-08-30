

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
import Ocean
import json

# storage hierarchy

import sqlite3

def setup_database():
    # Connect to (or create) the SQLite database
    conn = sqlite3.connect('cyber_prompts.db')
    cursor = conn.cursor()

    # 1. Create the hierarchy table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            parent_id INTEGER,
            FOREIGN KEY (parent_id) REFERENCES categories (id)
        )
    ''')
    
    # 2. Create the table for saving the allowed prompts
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

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app) 
# app states
state = {
    "token": None,
    "duckdb_conn": None,
}

def _connect_and_load(manager_url, indexer_url, wazuh_user, wazuh_pass, indexer_user, indexer_pass):
    """Authenticate with Wazuh and load alerts into DuckDB using the given
    credentials. Used by both /api/login and (optionally) startup.
    manager_url: Wazuh manager URL
    indexer_url: Wazuh indexer URL
    wazuh_user: Wazuh username
    wazuh_pass: Wazuh password
    indexer_user: Wazuh indexer username
    indexer_pass: Wazuh indexer password"""
    token = Ocean.get_wazuh_token(manager_url, wazuh_user, wazuh_pass)
    if token is None:
        return False, "Could not authenticate with the Wazuh manager. Check your username and password."

    alerts = Ocean.get_alerts(indexer_url, indexer_user, indexer_pass)
    processed = Ocean.process_alerts(alerts)
    conn = Ocean.load_into_duckdb(processed)

    
    Ocean.MANAGER_URL = manager_url
    Ocean.INDEXER_URL = indexer_url
    Ocean.INDEXER_USERNAME = indexer_user
    Ocean.INDEXER_PASSWORD = indexer_pass

    state["token"] = token
    state["duckdb_conn"] = conn
    return True, f"Connected — loaded {len(processed)} alerts."


# Routes 

MODEL_OPTIONS = {
    "ollama": ["qwen2.5", "qwen2.5:0.5b", "qwen2.5:1.5b", "llama3", "mistral", "Ocean"],
    "anthropic": ["claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5"],
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
}

@app.route("/api/model-options", methods=["GET"])
def model_options():
    return jsonify({
        "options": MODEL_OPTIONS,
        "current": {
            "provider": Ocean.llm_config["provider"],
            "model": Ocean.llm_config["model"],
        },
    })


@app.route("/api/set-model", methods=["POST"])
def set_model():
    '''Set the LLM provider and model. Expects JSON body with keys:'''
    body = request.get_json(silent=True) or {}
    provider = body.get("provider")
    model = body.get("model")
    api_key = body.get("api_key")  # not required for ollama

    if not provider or not model:
        return jsonify({"error": "Missing 'provider' or 'model'"}), 400
    if provider in ("anthropic", "openai") and not api_key:
        return jsonify({"error": f"{provider} requires an API key"}), 400

    Ocean.set_llm_config(provider, model, api_key)
    return jsonify({"message": f"Now using {provider}: {model}"})

@app.route("/", methods=["GET"])
def index():
    """Serve the React frontend."""
    """Serve the plain HTML/JS interface — no Node/npm required."""
    return send_from_directory(".", "index.html")

@app.route("/api/config", methods=["GET"])
def config():
    """Return non-secret defaults so the login form can be pre-filled.
    Never returns passwords."""
    return jsonify({
        "manager_url": Ocean.MANAGER_URL or "https://localhost:55000",
        "indexer_url": Ocean.INDEXER_URL or "https://localhost:9200",
        "wazuh_username": Ocean.WAZUH_USERNAME or "",
        "indexer_username": Ocean.INDEXER_USERNAME or "",
    })


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    required = ["manager_url", "indexer_url", "wazuh_username", "wazuh_password",
                "indexer_username", "indexer_password"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    success, message = _connect_and_load(
        body["manager_url"], body["indexer_url"],
        body["wazuh_username"], body["wazuh_password"],
        body["indexer_username"], body["indexer_password"],
    )
    if not success:
        return jsonify({"error": message}), 401
    return jsonify({"message": message})

@app.route("/api/health", methods=["GET"])
def health():
    wazuh_ok = state["token"] is not None
    duckdb_ok = state["duckdb_conn"] is not None
    row_count = 0
    if duckdb_ok:
        try:
            row_count = state["duckdb_conn"].execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        except Exception:
            row_count = 0
    return jsonify({
        "wazuh_authenticated": wazuh_ok,
        "duckdb_ready": duckdb_ok,
        "threats_row_count": row_count,
        "model": Ocean.OLLAMA_MODEL,
    })


@app.route("/api/agents", methods=["GET"])
def agents():
    """Return a list of Wazuh agents."""
    if not state["token"]:
        return jsonify({"error": "Not authenticated with Wazuh"}), 503
    data = Ocean.get_agents(Ocean.MANAGER_URL, state["token"])
    return jsonify(data)


@app.route("/api/refresh", methods=["POST"])
def refresh():
    """Refresh the DuckDB database with the latest alerts from Wazuh."""
    if not state["duckdb_conn"]:
        return jsonify({"error": "DuckDB not initialized"}), 503
    count = Ocean.refresh_threats(
        state["duckdb_conn"], Ocean.INDEXER_URL,
        Ocean.INDEXER_USERNAME, Ocean.INDEXER_PASSWORD
    )
    return jsonify({"status": "refreshed", "rows": count})


@app.route("/api/latest-alert", methods=["GET"])
def latest_alert():
    """Return the single most recent raw alert (full nested JSON) for
    the Alert Analyzer component's 'Fetch Live Alert' button.
    method: GET /api/latest-alert
    """
    alert = Ocean.get_latest_alert(
        Ocean.INDEXER_URL, Ocean.INDEXER_USERNAME, Ocean.INDEXER_PASSWORD
    )
    if alert is None:
        return jsonify({"error": "No alerts found"}), 404
    return jsonify(alert)


@app.route("/api/query", methods=["POST"])
def query():
    """Accept a natural language question, generate SQL, and return results."""
    body = request.get_json(silent=True) or {}
    question = body.get("question", "").strip()

    if not question:
        return jsonify({"error": "Missing 'question' in request body"}), 400
    if not state["duckdb_conn"]:
        return jsonify({"error": "DuckDB not initialized"}), 503

    sql, result_df, summary = Ocean.query_engine(question, state["duckdb_conn"])
    viz = Ocean.describe_result(result_df)

    return jsonify({
        "question": question,
        "sql": sql,
        "summary": summary,
        "visualization": viz,
    })


def log_query_to_file(question, sql, result_df, path="query_log.txt"):
    """Append every user query and its generated SQL to a plain text log.
    question: the user's natural language question
    sql: the SQL generated by the query engine"""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}]\n")
        f.write(f"Question: {question}\n")
        f.write(f"SQL: {sql}\n")
        f.write("-" * 60 + "\n")
        f.write(f"Rows returned: {len(result_df) if result_df is not None else 0}\n")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)