# Ocean — Cybersecurity Query Assistant

Ask questions about your Wazuh security data in plain English. Ocean turns
your question into a SQL query, runs it against live alert data, and shows
you a chart, table, or answer — right in your browser.

---

## What you need installed (one-time)

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — runs Wazuh
- [Ollama](https://ollama.com/download) — runs the local AI model
- Python 3.10+
- Node.js is **not** required — Ocean has no separate frontend build step

---

## First-time setup

```powershell
python -m pip install -r requirements.txt
ollama pull qwen2.5
```

That's it — no `.env` file to fill in by hand. You'll enter your Wazuh
credentials directly in the app the first time you open it.

---

## Every time you want to use Ocean

**Step 1 — Start Wazuh**
```powershell
cd wazuh-docker\single-node
docker-compose up -d
```
Wait about a minute, then check everything is running:
```powershell
docker ps
```
You should see `manager`, `indexer`, and `dashboard` all listed as `Up`.

**Step 2 — Start Ocean**
```powershell
cd C:\Users\doubl\Documents\Ocean
.\run.ps1
```

**Step 3 — Open it in your browser**
```
http://localhost:5000
```

You'll see a short loading screen, then a login screen asking for your
Wazuh username/password. Enter them once, click **Connect**, and you're in.

---

## Using Ocean

- **Query tab** — type a question like *"show me critical alerts from this week"* and press Enter. Ocean replies with an explanation, the SQL it used, and a chart or table.
- **Alert Analyzer tab** — paste a raw alert, or click **Fetch Live Alert** to pull the most recent one, to see a risk score, MITRE ATT&CK mapping, and an exportable report.
- **Sidebar (💬)** — every question you ask is saved as its own chat. Click **+ New Chat** to start fresh, or click an old chat to pick up where you left off.
- **Sidebar (⚙️)** — choose which AI model powers Ocean (a local Ollama model, or your own Anthropic/OpenAI API key).

---

## If something won't start

| Problem | Try this |
|---|---|
| Login screen says "Could not authenticate" | Double-check your Wazuh username/password |
| Page won't load at all | Make sure `.\run.ps1` is still running in a terminal |
| Wazuh containers won't start | `docker logs single-node-wazuh.manager-1 --tail 50` to see why |
| Responses take a long time | Try a smaller model in the ⚙️ Model Settings panel, e.g. `qwen2.5:0.5b` |

---

## Project files (for reference — you don't need to edit these to use Ocean)

```
Ocean.py       — the pipeline: Wazuh, DuckDB, AI translation
api.py          — the server that ties everything together
index.html      — the interface you see in the browser
rag.py          — remembers past questions to answer faster
soul.md         — Ocean's personality/instructions
run.ps1         — starts everything with one command
requirements.txt — Python packages needed
```
