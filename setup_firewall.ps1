# Windows Firewall Setup for Honeypot
# Run this script as Administrator

Write-Host "=== Honeypot Firewall Configuration ===" -ForegroundColor Green
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Running as Administrator" -ForegroundColor Green
Write-Host ""

# Ports to allow
$ports = @(
    @{Name="SSH Honeypot"; Port=2222},
    @{Name="HTTP Honeypot"; Port=8080},
    @{Name="HTTPS Honeypot"; Port=8443},
    @{Name="FTP Honeypot"; Port=2121},
    @{Name="MySQL Honeypot"; Port=3306},
    @{Name="Honeypot Dashboard"; Port=5001}
)

Write-Host "Creating firewall rules for honeypot ports..." -ForegroundColor Cyan
Write-Host ""

foreach ($rule in $ports) {
    $ruleName = $rule.Name
    $port = $rule.Port
    
    # Check if rule already exists
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if ($existingRule) {
        Write-Host "[SKIP] Firewall rule '$ruleName' already exists" -ForegroundColor Yellow
    } else {
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -LocalPort $port `
                -Protocol TCP `
                -Action Allow `
                -Enabled True | Out-Null
            Write-Host "[OK] Created firewall rule: $ruleName (Port $port)" -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Failed to create rule '$ruleName': $_" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "=== Firewall Configuration Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Ports now allowed (inbound):" -ForegroundColor Cyan
foreach ($rule in $ports) {
    Write-Host "  - $($rule.Name): Port $($rule.Port)" -ForegroundColor White
}

Write-Host ""
Write-Host "=== Next Steps ===" -ForegroundColor Yellow
Write-Host "1. If behind router, configure port forwarding (see CONNECTION_GUIDE.md)" -ForegroundColor White
Write-Host "2. Find your public IP: Visit https://whatismyipaddress.com/" -ForegroundColor White
Write-Host "3. Share connection info with others:" -ForegroundColor White
Write-Host "   ssh -p 2222 admin@YOUR_PUBLIC_IP" -ForegroundColor Cyan

