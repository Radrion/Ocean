# ─────────────────────────────────────────────────────────────
# Hermes — launch script (plain HTML/JS version, no npm needed)
# Starts Ollama, then the Flask API which also serves the interface.
#     .\run.ps1
# ─────────────────────────────────────────────────────────────

Write-Host "==> Checking if Ollama is already running..." -ForegroundColor Cyan
$ollamaRunning = Get-Process ollama -ErrorAction SilentlyContinue

if (-not $ollamaRunning) {
    Write-Host "==> Starting Ollama in the background..." -ForegroundColor Cyan
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "Ollama is already running." -ForegroundColor Green
}

Write-Host "==> Reminder: make sure Wazuh (Docker) is running:" -ForegroundColor Yellow
Write-Host "    cd wazuh-docker/single-node && docker-compose up -d" -ForegroundColor Yellow
Write-Host ""

Write-Host "==> Launching Hermes..." -ForegroundColor Cyan
Write-Host "==> Once started, open http://localhost:5000 in your browser" -ForegroundColor Green
Write-Host ""

python api.py