# Professional Dashboard Startup Script for Windows
# Run with: .\run_dashboard.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Professional Honeypot Dashboard          " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Detect Python
Write-Host "[*] Detecting Python..." -ForegroundColor Blue
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1 | Out-String
        if ($version -match "Python 3\.(\d+)") {
            $python = $cmd
            Write-Host "[+] Found Python: $version" -ForegroundColor Green
            break
        }
    } catch {
        continue
    }
}

if (-not $python) {
    Write-Host "[-] Python 3.8+ is required but not found" -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/"
    exit 1
}

# Check for virtual environment
$venvPath = ".\.venv"
if (Test-Path $venvPath) {
    Write-Host "[*] Activating virtual environment..." -ForegroundColor Blue
    & "$venvPath\Scripts\Activate.ps1"
    $python = "$venvPath\Scripts\python.exe"
    Write-Host "[+] Virtual environment activated" -ForegroundColor Green
}

# Check for required packages
Write-Host "[*] Checking required packages..." -ForegroundColor Blue
$packages = @("flask", "requests", "markupsafe")
$missing = @()

foreach ($pkg in $packages) {
    try {
        & $python -c "import $pkg" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] $pkg is installed" -ForegroundColor Green
        } else {
            $missing += $pkg
        }
    } catch {
        $missing += $pkg
    }
}

if ($missing.Count -gt 0) {
    Write-Host "[*] Installing missing packages..." -ForegroundColor Blue
    foreach ($pkg in $missing) {
        Write-Host "[*] Installing $pkg..." -ForegroundColor Blue
        & $python -m pip install $pkg --quiet
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Installed $pkg" -ForegroundColor Green
        } else {
            Write-Host "[-] Failed to install $pkg" -ForegroundColor Red
        }
    }
}

# Set environment variables
if (-not $env:DASHBOARD_USERNAME) { $env:DASHBOARD_USERNAME = "admin" }
if (-not $env:DASHBOARD_PASSWORD) { $env:DASHBOARD_PASSWORD = "honeypot@91771" }
if (-not $env:FLASK_RUN_PORT) { $env:FLASK_RUN_PORT = "5001" }
if (-not $env:ATTACKS_LOG) { $env:ATTACKS_LOG = "logs\attacks.json" }
if (-not $env:GEOCACHE_FILE) { $env:GEOCACHE_FILE = "logs\geocache.json" }

# Create logs directory
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    Write-Host "[+] Created logs directory" -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Starting Professional Dashboard           " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Start dashboard
Write-Host "[*] Starting dashboard..." -ForegroundColor Blue
Write-Host "[*] Access at: http://localhost:$env:FLASK_RUN_PORT" -ForegroundColor Yellow
Write-Host "[*] Username: $env:DASHBOARD_USERNAME" -ForegroundColor Yellow
Write-Host "[*] Password: $env:DASHBOARD_PASSWORD" -ForegroundColor Yellow
Write-Host ""
Write-Host "[*] Features:" -ForegroundColor Cyan
Write-Host "    - Real-time attack monitoring" -ForegroundColor White
Write-Host "    - Search and filter capabilities" -ForegroundColor White
Write-Host "    - CSV export functionality" -ForegroundColor White
Write-Host "    - Auto-refresh every 30 seconds" -ForegroundColor White
Write-Host "    - Geographic visualization" -ForegroundColor White
Write-Host ""
Write-Host "[*] Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host ""

& $python app.py

