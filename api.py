"""
api.py — Flask API layer between the React (.jsx) frontend and hermes.py.

Run with:
    python api.py

Exposes:
    GET  /api/health          -> connection status for Wazuh/DuckDB/Ollama
    GET  /api/agents          -> list of monitored machines
    POST /api/query           -> { "question": "..." } -> sql + result
    POST /api/refresh         -> pull fresh alerts from Wazuh into DuckDB
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

import hermes

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)  # kept for flexibility if you ever call the API from another origin

# ── App-level state, built once at startup ──────────────────────────────
state = {
    "token": None,
    "duckdb_conn": None,
}


def _bootstrap():
    """Run once when the API starts: authenticate, pull alerts, load DuckDB."""
    print("Starting Hermes API...")

    token = hermes.get_wazuh_token(
        hermes.MANAGER_URL, hermes.WAZUH_USERNAME, hermes.WAZUH_PASSWORD
    )
    state["token"] = token

    alerts = hermes.get_alerts(
        hermes.INDEXER_URL, hermes.INDEXER_USERNAME, hermes.INDEXER_PASSWORD
    )
    processed = hermes.process_alerts(alerts)
    state["duckdb_conn"] = hermes.load_into_duckdb(processed)

    print("Hermes API ready.")


# ── Routes ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Serve the plain HTML/JS interface — no Node/npm required."""
    return send_from_directory(".", "index.html")


@app.route("/api/health", methods=["GET"])
def health():
    wazuh_ok = state["token"] is not None
    duckdb_ok = state["duckdb_conn"] is not None
    return jsonify({
        "wazuh_connected": wazuh_ok,
        "duckdb_ready": duckdb_ok,
        "model": hermes.OLLAMA_MODEL,
    })


@app.route("/api/agents", methods=["GET"])
def agents():
    if not state["token"]:
        return jsonify({"error": "Not authenticated with Wazuh"}), 503
    data = hermes.get_agents(hermes.MANAGER_URL, state["token"])
    return jsonify(data)


@app.route("/api/refresh", methods=["POST"])
def refresh():
    if not state["duckdb_conn"]:
        return jsonify({"error": "DuckDB not initialized"}), 503
    count = hermes.refresh_threats(
        state["duckdb_conn"], hermes.INDEXER_URL,
        hermes.INDEXER_USERNAME, hermes.INDEXER_PASSWORD
    )
    return jsonify({"status": "refreshed", "rows": count})


@app.route("/api/latest-alert", methods=["GET"])
def latest_alert():
    """Return the single most recent raw alert (full nested JSON) for
    the Alert Analyzer component's 'Fetch Live Alert' button."""
    alert = hermes.get_latest_alert(
        hermes.INDEXER_URL, hermes.INDEXER_USERNAME, hermes.INDEXER_PASSWORD
    )
    if alert is None:
        return jsonify({"error": "No alerts found"}), 404
    return jsonify(alert)


@app.route("/api/query", methods=["POST"])
def query():
    body = request.get_json(silent=True) or {}
    question = body.get("question", "").strip()

    if not question:
        return jsonify({"error": "Missing 'question' in request body"}), 400
    if not state["duckdb_conn"]:
        return jsonify({"error": "DuckDB not initialized"}), 503

    sql, result_df = hermes.query_engine(question, state["duckdb_conn"])
    viz = hermes.describe_result(result_df)

    return jsonify({
        "question": question,
        "sql": sql,
        "visualization": viz,
    })


if __name__ == "__main__":
    _bootstrap()
    app.run(host="0.0.0.0", port=5000, debug=False)