# PowerShell startup script for Honeypot System on Windows
# Run with: .\start.ps1 or powershell -ExecutionPolicy Bypass -File start.ps1

param(
    [switch]$Help,
    [switch]$SkipMenu
)

# Check if boot menu should be shown
if (-not $SkipMenu) {
    # Show boot menu
    try {
        python boot_menu.py 2>$null
        if ($LASTEXITCODE -eq 0) {
            exit 0
        }
    } catch {
        # If Python or boot menu fails, continue with normal startup
        Write-Host "Boot menu not available, starting honeypot directly..." -ForegroundColor Yellow
    }
}

# Script configuration
$ErrorActionPreference = "Continue"

# Color output functions
function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# Help message
if ($Help) {
    Write-Host @"
Honeypot System Startup Script for Windows

Usage: .\start.ps1 [options]

Options:
    -Help          Show this help message

Environment Variables (optional):
    DASHBOARD_USERNAME    Dashboard username (default: admin)
    DASHBOARD_PASSWORD    Dashboard password (default: honeypot@91771)
    FLASK_RUN_PORT        Dashboard port (default: 5001)
    ATTACKS_LOG           Path to attacks log (default: logs/attacks.json)
    GEOCACHE_FILE         Path to geocache (default: logs/geocache.json)

Requirements:
    - Python 3.8+
    - Administrator privileges (for privileged ports)
    - Required packages: paramiko, flask, requests, markupsafe

Note: This script is designed for Windows. For Linux/Mac, use start.sh

"@
    exit 0
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Honeypot System - Windows Startup        " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Detect Python
Write-Status "Detecting Python installation..."
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1 | Out-String
        if ($version -match "Python 3\.(\d+)") {
            $python = $cmd
            Write-Success "Found Python: $version"
            break
        }
    } catch {
        continue
    }
}

if (-not $python) {
    Write-Error-Custom "Python 3.8+ is required but not found"
    Write-Host "Please install Python from https://www.python.org/downloads/"
    exit 1
}

# Check for virtual environment
$venvPath = ".\.venv"
if (Test-Path $venvPath) {
    Write-Status "Activating virtual environment..."
    & "$venvPath\Scripts\Activate.ps1"
    $python = "$venvPath\Scripts\python.exe"
    Write-Success "Virtual environment activated"
} else {
    Write-Warning-Custom "No virtual environment found at $venvPath"
    Write-Warning-Custom "Consider creating one: python -m venv .venv"
}

# Create necessary directories
Write-Status "Creating necessary directories..."
$directories = @("ssh_keys", "certs", "logs", "config", "pcaps", "templates")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Success "Created directory: $dir"
    }
}

# Check for required Python packages
Write-Status "Checking required Python packages..."
$packages = @("paramiko", "flask", "requests", "markupsafe")
$missing = @()

foreach ($pkg in $packages) {
    try {
        & $python -c "import $pkg" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$pkg is installed"
        } else {
            $missing += $pkg
        }
    } catch {
        $missing += $pkg
    }
}

if ($missing.Count -gt 0) {
    Write-Status "Installing missing packages..."
    foreach ($pkg in $missing) {
        Write-Status "Installing $pkg..."
        & $python -m pip install $pkg --quiet
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Installed $pkg"
        } else {
            Write-Error-Custom "Failed to install $pkg"
        }
    }
}

# Check for OpenSSL (for certificates)
Write-Status "Checking for OpenSSL..."
$opensslFound = $false
try {
    $null = Get-Command openssl -ErrorAction Stop
    $opensslFound = $true
    Write-Success "OpenSSL found"
} catch {
    Write-Warning-Custom "OpenSSL not found. HTTPS may not work without certificates."
    Write-Warning-Custom "Download from: https://slproweb.com/products/Win32OpenSSL.html"
}

# Generate SSL certificates if needed and OpenSSL available
if ($opensslFound -and -not (Test-Path "certs\server.crt")) {
    Write-Status "Generating SSL certificates..."
    & openssl req -x509 -newkey rsa:2048 -keyout certs\server.key -out certs\server.crt -days 365 -nodes -subj "/CN=localhost" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "SSL certificates generated"
    }
} elseif (Test-Path "certs\server.crt") {
    Write-Success "Using existing SSL certificates"
}

# Check ports
Write-Status "Checking port availability..."
$ports = @(2222, 5001, 8080, 8443, 2121, 3306)
$portsInUse = @()

foreach ($port in $ports) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        $portsInUse += $port
        Write-Warning-Custom "Port $port is in use"
    }
}

if ($portsInUse.Count -gt 0) {
    Write-Warning-Custom "Some ports are in use. You may need to stop other services or change ports."
    Write-Host "Ports in use: $($portsInUse -join ', ')"
}

# Set environment variables
Write-Status "Setting environment variables..."
if (-not $env:DASHBOARD_USERNAME) { $env:DASHBOARD_USERNAME = "admin" }
if (-not $env:DASHBOARD_PASSWORD) { $env:DASHBOARD_PASSWORD = "honeypot@91771" }
if (-not $env:FLASK_RUN_PORT) { $env:FLASK_RUN_PORT = "5001" }
if (-not $env:ATTACKS_LOG) { $env:ATTACKS_LOG = "logs\attacks.json" }
if (-not $env:GEOCACHE_FILE) { $env:GEOCACHE_FILE = "logs\geocache.json" }

Write-Success "Environment configured"

# Start services
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Starting Honeypot Services               " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

Write-Status "Starting Unified Honeypot..."
$honeypotJob = Start-Job -ScriptBlock {
    param($pythonPath)
    Set-Location $using:PWD
    & $pythonPath unified_honeypot.py
} -ArgumentList $python

Start-Sleep -Seconds 3

Write-Status "Starting Dashboard..."
$dashboardJob = Start-Job -ScriptBlock {
    param($pythonPath)
    Set-Location $using:PWD
    $env:FLASK_RUN_PORT = $using:env:FLASK_RUN_PORT
    $env:DASHBOARD_USERNAME = $using:env:DASHBOARD_USERNAME
    $env:DASHBOARD_PASSWORD = $using:env:DASHBOARD_PASSWORD
    $env:ATTACKS_LOG = $using:env:ATTACKS_LOG
    $env:GEOCACHE_FILE = $using:env:GEOCACHE_FILE
    & $pythonPath app.py
} -ArgumentList $python

Start-Sleep -Seconds 3

# Get local IP
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch "127.0.0.1|169.254"} | Select-Object -First 1).IPAddress
if (-not $localIP) { $localIP = "localhost" }

Write-Host ""
Write-Success "All services started successfully!"
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Service Information                       " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Dashboard:  http://${localIP}:5001" -ForegroundColor Yellow
Write-Host "  Username: $env:DASHBOARD_USERNAME"
Write-Host "  Password: $env:DASHBOARD_PASSWORD"
Write-Host ""
Write-Host "Services running on:" -ForegroundColor Yellow
Write-Host "  SSH:      Port 2222"
Write-Host "  HTTP:     Port 8080"
Write-Host "  HTTPS:    Port 8443"
Write-Host "  FTP:      Port 2121"
Write-Host "  MySQL:    Port 3306"
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Status "Press Ctrl+C to stop all services"
Write-Host ""

# Monitor jobs
try {
    while ($true) {
        # Check if jobs are still running
        if ($honeypotJob.State -ne "Running") {
            Write-Error-Custom "Honeypot service stopped unexpectedly"
            break
        }
        if ($dashboardJob.State -ne "Running") {
            Write-Error-Custom "Dashboard service stopped unexpectedly"
            break
        }
        
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host ""
    Write-Status "Shutting down services..."
    
    Stop-Job $honeypotJob -ErrorAction SilentlyContinue
    Stop-Job $dashboardJob -ErrorAction SilentlyContinue
    Remove-Job $honeypotJob -ErrorAction SilentlyContinue
    Remove-Job $dashboardJob -ErrorAction SilentlyContinue
    
    Write-Success "All services stopped"
    Write-Host ""
}
