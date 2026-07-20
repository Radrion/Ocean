# ─────────────────────────────────────────────────────────────
# Hermes — one-time setup script
# Run this once after cloning the repo:
#     .\setup.ps1
# ─────────────────────────────────────────────────────────────

Write-Host "==> Checking Python..." -ForegroundColor Cyan
python --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Python not found. Install it from https://www.python.org/downloads/ and re-run this script." -ForegroundColor Red
    exit 1
}

Write-Host "==> Installing Python dependencies..." -ForegroundColor Cyan
python -m pip install -r requirements.txt

Write-Host "==> Checking Ollama..." -ForegroundColor Cyan
$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Write-Host "Ollama not found. Download it from https://ollama.com/download, install it, then re-run this script." -ForegroundColor Red
    exit 1
}

Write-Host "==> Pulling Qwen2.5 model (this may take a few minutes)..." -ForegroundColor Cyan
ollama pull qwen2.5

Write-Host "==> Checking Docker (for Wazuh)..." -ForegroundColor Cyan
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Host "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/ if you plan to run Wazuh locally with docker-compose." -ForegroundColor Yellow
} else {
    Write-Host "Docker found. See README.md for how to start Wazuh with docker-compose." -ForegroundColor Green
}

Write-Host "==> Creating your .env file..." -ForegroundColor Cyan
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example — open it and fill in your real credentials." -ForegroundColor Yellow
} else {
    Write-Host ".env already exists — leaving it untouched." -ForegroundColor Green
}

Write-Host ""
Write-Host "==> Setup complete!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Edit .env with your real Wazuh credentials and URLs"
Write-Host "  2. Make sure Wazuh is running (see README.md)"
Write-Host "  3. Run .\run.ps1 to launch Hermes"