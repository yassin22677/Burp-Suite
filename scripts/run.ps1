# Run the Burp RL backend (from repo root:  .\scripts\run.ps1 )
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Test-Path (Join-Path $root ".env"))) {
    if (Test-Path (Join-Path $root ".env.example")) {
        Copy-Item (Join-Path $root ".env.example") (Join-Path $root ".env")
        Write-Host "Created .env from .env.example — edit DATABASE_URL if needed." -ForegroundColor Yellow
    }
}

python -m pip install -r requirements.txt
Write-Host "Starting http://127.0.0.1:5000 ..." -ForegroundColor Green
python run.py
