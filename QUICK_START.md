# 🚀 Quick Start Guide

## Windows

### 1. Install Python 3.8+
Download from: https://www.python.org/downloads/

### 2. Install Dependencies
```powershell
pip install paramiko flask requests markupsafe cryptography
```

### 3. Start the System
```powershell
# Option 1: Use PowerShell script
.\run_dashboard.ps1

# Option 2: Manual start
python unified_honeypot.py    # Terminal 1
python app.py                  # Terminal 2
```

### 4. Access Dashboard
- **URL**: http://localhost:5001
- **Username**: `admin`
- **Password**: `honeypot@91771`

## Linux/macOS

### 1. Install Python 3.8+
```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip python3-venv

# macOS
brew install python3
```

### 2. Install Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install paramiko flask requests markupsafe cryptography
```

### 3. Start the System
```bash
chmod +x start.sh
sudo ./start.sh
```

### 4. Access Dashboard
- **URL**: http://localhost:5001
- **Username**: `admin`
- **Password**: `honeypot@91771`

### 5. Connect to SSH Honeypot
- **Command**: `ssh -p 2222 admin@localhost` (or `ssh -p 2222 admin@YOUR_IP`)
- **Username**: `admin`
- **Password**: ANY (all passwords work - enter any password when prompted)

## Configuration (Optional)

### Set Alert Thresholds
```bash
# Linux/macOS
export ALERT_HIGH_RATE=10
export ALERT_REPEATED_IP=5
export WEBHOOK_URL="https://your-webhook.com/alerts"

# Windows PowerShell
$env:ALERT_HIGH_RATE=10
$env:ALERT_REPEATED_IP=5
$env:WEBHOOK_URL="https://your-webhook.com/alerts"
```

### Change Dashboard Credentials
```bash
# Linux/macOS
export DASHBOARD_USERNAME="your_username"
export DASHBOARD_PASSWORD="your_password"

# Windows PowerShell
$env:DASHBOARD_USERNAME="your_username"
$env:DASHBOARD_PASSWORD="your_password"
```

## Dashboard Features

### 🔔 Real-Time Alerts
- Click notification badge (🔔) to view alerts
- Alerts appear automatically for critical events
- Toast notifications for high-severity alerts

### 🔍 Filter Attacks
1. Click "🔍 Filter" button
2. Set criteria (date, service, attack type, country, IP)
3. Click "Apply Filters"

### 📊 Export Data
1. Click "📊 Export" button
2. Choose format (CSV/JSON)
3. Set date range (optional)
4. Click "Export"

### 🔎 Search
- Type in search box above table
- Real-time filtering as you type

## Troubleshooting

### Port Already in Use
```bash
# Linux
sudo lsof -i :5001
sudo kill -9 <PID>

# Windows
netstat -ano | findstr :5001
taskkill /PID <PID> /F
```

### Dashboard Not Loading
- Check if `app.py` is running
- Verify port 5001 is not blocked
- Check browser console for errors

### Alerts Not Showing
- Check `logs/alerts.json` exists
- Verify alert thresholds are set
- Check browser console for SSE connection

## Need Help?

See full documentation in [README.md](README.md)

