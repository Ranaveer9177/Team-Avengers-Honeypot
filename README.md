# 🛡️ Team Avengers — Multi-Service Honeypot System v4.1

A professional-grade honeypot system with multi-service attack detection, real-time alerting, automated incident response, and a modern dark-themed security dashboard with a premium login interface.

## 🚀 Features

### Core Capabilities
- **Multi-Service Simulation**: SSH, HTTP, HTTPS, FTP, MySQL honeypots
- **Advanced Attack Detection**: Pattern recognition, tool detection, device fingerprinting
- **Real-Time Dashboard**: Secure web interface with tabbed navigation (Dashboard, Logs, Connections)
- **Premium Login Page**: Split-panel login UI with particle animations, password toggle, and auto-generated credentials
- **Auto-Generated Credentials**: Random 8-character password (letters, digits, special chars) regenerated on every startup
- **Real-Time Alerting**: Server-Sent Events (SSE) for instant threat notifications
- **Automated Incident Response**: Webhook notifications, email alerts, IP blocking
- **IP Geolocation**: Dual API fallback (ip-api.com + ipinfo.io) with LRU cache
- **World Map**: Interactive Leaflet map showing live attack origins
- **Interactive Boot Menu**: CLI menu with Open / Encrypted honeypot modes

### Dashboard Tabs

| Tab | Features |
|---|---|
| **Dashboard** | Stat cards, doughnut charts (Service/Attack Type/Country), interactive world map |
| **Attack Logs** | Paginated table, real-time search, sortable columns, expandable row details, CSV export |
| **Connections** | Top attackers leaderboard, geographic analysis, ISP detection, attack timeline |

### Security & Quality
- Thread-safe geocache with `threading.Lock()`
- Batch geocache writes (every 10 lookups instead of every request)
- Separate connection timeouts (SSH persistent, others 30s)
- IP validation on filter API using `ipaddress` module
- Session-based form login with Flask sessions (no Basic Auth popups)
- Auto-generated random password on every startup (shown in console)
- Restrictive file permissions for SSH keys and SSL certificates

## 📋 Requirements

### System Requirements
- **Python 3.8+** (3.11+ recommended)
- **Operating Systems**: 
  - **Kali Linux** (recommended for deployment)
  - Ubuntu, Debian, CentOS, RHEL, Fedora, Arch, SUSE
  - Windows 10/11 (PowerShell 5.1+)
  - macOS
- **Root/sudo privileges** (for binding to privileged ports on Linux)

### Required Ports

| Port | Service |
|---|---|
| 2222 | SSH Honeypot |
| 5001 | Dashboard (Flask) |
| 8080 | HTTP Honeypot |
| 8443 | HTTPS Honeypot |
| 2121 | FTP Honeypot |
| 3306 | MySQL Honeypot |

### Python Packages
```bash
pip install -r requirements.txt
```
Or manually:
```bash
pip install paramiko flask requests markupsafe cryptography
```

## 🏗️ Project Structure

```
Team-Avengers-Honeypot/
├── unified_honeypot.py      # Core honeypot server (SSH, HTTP, HTTPS, FTP, MySQL)
├── app.py                   # Flask dashboard with API endpoints & alerting
├── device_detector.py       # Device/client fingerprinting utility
├── boot_menu.py             # Interactive CLI boot menu
├── setup.py                 # Python packaging
├── start.sh                 # Linux/macOS startup script
├── start.ps1                # Windows PowerShell startup script
├── launch.sh                # Linux/Mac launcher (shows boot menu)
├── launch.bat               # Windows launcher (shows boot menu)
├── requirements.txt         # Python dependencies
├── pytest.ini               # Test configuration
├── config/
│   ├── unified_honeypot.json    # Honeypot configuration
│   └── .flask_secret.key        # Flask session secret (auto-generated)
├── templates/
│   ├── unified_dashboard.html   # Main dashboard (tabbed UI)
│   └── login.html               # Premium login page
├── static/
│   ├── css/style.css            # Dark-themed dashboard styles
│   ├── css/login.css            # Login page styles
│   └── js/dashboard.js          # Dashboard logic (charts, export, reset)
├── tests/
│   ├── test_app.py              # Dashboard tests
│   ├── test_config.py           # Config parsing tests
│   ├── test_dashboard.py        # Data sanitization tests
│   ├── test_device_detector.py  # Device detection tests
│   └── test_honeypot.py         # Honeypot logic tests
├── logs/
│   ├── attacks.json             # Attack log (JSON lines)
│   ├── alerts.json              # Alert log (JSON lines)
│   ├── geocache.json            # IP geolocation cache
│   ├── backups/                 # Reset backups
│   └── unified_honeypot.log     # Service logs
├── certs/                   # SSL certificates (auto-generated)
├── ssh_keys/                # SSH host keys (auto-generated)
└── pcaps/                   # Network capture files
```

## 🚀 Quick Start

### Kali Linux (Recommended)

```bash
# 1. Clone
git clone https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
cd Team-Avengers-Honeypot

# 2. Install dependencies
sudo apt update && sudo apt install -y python3 python3-pip python3-venv openssl
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Start (one-click)
sudo bash start.sh

# 4. Access dashboard
# URL:      http://localhost:5001
# Username: admin
# Password: (random — shown in console on each startup)
```

### Manual Start (Any OS)

```bash
# Terminal 1: Honeypot services
sudo python3 unified_honeypot.py

# Terminal 2: Dashboard
python3 app.py
```

### Windows

```powershell
# Boot menu
python boot_menu.py
# or
.\launch.bat

# PowerShell script
.\start.ps1

# Manual
python unified_honeypot.py   # Terminal 1
python app.py                # Terminal 2
```

### Access the Dashboard
- **URL**: `http://localhost:5001` → redirects to login page
- **Username**: `admin`
- **Password**: Random — generated fresh on each startup (printed in console)
- To use a **fixed password**: set `DASHBOARD_PASSWORD` environment variable

## 🔬 Testing the Honeypot

```bash
# Test SSH honeypot
ssh -p 2222 admin@localhost

# Test HTTP honeypot
curl http://localhost:8080

# Test FTP honeypot
ftp -P 2121 localhost

# Test Dashboard API
curl -u admin:'YOUR_PASSWORD' http://localhost:5001/api/attacks
```

## ⚙️ Configuration

### Environment Variables

```bash
# Dashboard credentials (override auto-generated password)
export DASHBOARD_USERNAME="admin"
export DASHBOARD_PASSWORD="your_custom_password"
export FLASK_RUN_PORT=5001

# Log file paths
export ATTACKS_LOG="logs/attacks.json"
export GEOCACHE_FILE="logs/geocache.json"
export ALERTS_LOG="logs/alerts.json"

# Geolocation API
export IP_API_URL="http://ip-api.com/json"
export IP_API_TIMEOUT=3.0

# Alert thresholds
export ALERT_HIGH_RATE=10
export ALERT_REPEATED_IP=5
export WEBHOOK_URL="https://your-webhook.com/alerts"
```

### Honeypot Config (`config/unified_honeypot.json`)

```json
{
  "ssh_port": 2222,
  "http_port": 8080,
  "https_port": 8443,
  "ftp_port": 2121,
  "mysql_port": 3306,
  "log_dir": "logs",
  "ssh_key_dir": "ssh_keys",
  "cert_dir": "certs",
  "pcap_dir": "pcaps",
  "pcap_enabled": true,
  "initial_payload_max_bytes": 512,
  "banners": {
    "ssh_version": "SSH-2.0-OpenSSH_7.4",
    "http_server": "Apache/2.4.41 (Ubuntu)"
  }
}
```

## 📡 API Endpoints

Browser routes use session-based login (form at `/login`). API endpoints also accept HTTP Basic Auth for scripts/curl.

| Method | Endpoint | Description |
|---|---|---|
| `GET/POST` | `/login` | Login page (form-based authentication) |
| `GET` | `/logout` | Logout and clear session |
| `GET` | `/` | Dashboard HTML (requires auth) |
| `GET` | `/api/attacks` | Get attack data (JSON) |
| `GET` | `/api/alerts` | Get recent alerts |
| `GET` | `/api/alerts/stream` | SSE real-time alert stream |
| `POST` | `/api/attacks/filter` | Filter attacks by criteria |
| `POST` | `/api/attacks/export` | Export attacks (CSV/JSON) |
| `POST` | `/api/reset` | Reset dashboard (backup + clear) |
| `GET` | `/api/stats` | Statistics with optional date range |

See [API.md](API.md) for full documentation.

## 🔒 Security Features

- **Form-Based Login**: Premium login page with session-based authentication
- **Auto-Generated Passwords**: Fresh random 8-char password on every startup (uppercase, lowercase, digit, special char)
- **XSS Hardening**: Input sanitization and HTML escaping
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **Rate Limiting**: 45 req/min for geolocation API (thread-safe)
- **Auto-Generated SSL**: Certificates for HTTPS honeypot
- **CSRF Protection**: No credentials exposed in frontend JavaScript

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Current status: 16/16 tests passing ✅
```

### Test Coverage

| File | Coverage |
|---|---|
| `tests/test_app.py` | 100% |
| `tests/test_config.py` | 100% |
| `tests/test_dashboard.py` | 100% |
| `tests/test_device_detector.py` | 100% |
| `tests/test_honeypot.py` | 97% |

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Linux
sudo lsof -i :5001 && sudo kill -9 <PID>

# Windows
netstat -ano | findstr :5001
taskkill /PID <PID> /F
```

### Dashboard Not Accessible
- Verify port 5001 is not blocked by firewall
- Check if service started: `ps aux | grep app.py`
- Review logs: `tail -f logs/unified_honeypot.log`

### SSL Certificate Errors
- Certificates auto-generate on first run
- Regenerate: delete `certs/server.crt` and `certs/server.key`

### Geolocation Not Working
- Check internet connection
- Check API rate limits (45 req/min)
- System falls back to ipinfo.io automatically

## 🛡️ Security Best Practices

- ⚠️ **Never expose the dashboard to the internet** — use VPN or firewall
- ⚠️ **Password changes on every restart** — check console output each time
- ⚠️ **This is a honeypot** — do not use on production systems
- ⚠️ **Restrict dashboard access** with iptables rules
- ⚠️ **Monitor disk space** — PCAP files can grow large

```bash
# Restrict dashboard to your IP only
sudo iptables -A INPUT -p tcp --dport 5001 -s YOUR_ADMIN_IP -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5001 -j DROP
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

See the [LICENSE](LICENSE) file for details.

---

**Repository**: https://github.com/Ranaveer9177/Team-Avengers-Honeypot

**Version**: 4.1 — Login Page, Auto-Generated Credentials & Dashboard Enhancements

**Last Updated**: June 2026
