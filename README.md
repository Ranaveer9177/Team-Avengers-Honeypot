# 🛡️ Multi-Service Honeypot System v3.0

A sophisticated honeypot system with advanced attack detection, **real-time alerting**, automated incident response, comprehensive monitoring, and a modern web dashboard.

## 🚀 Features

### Core Capabilities
- **Multi-Service Simulation**: SSH, HTTP, HTTPS, FTP, MySQL
- **Advanced Attack Detection**: Pattern recognition, tool detection, device fingerprinting
- **Real-Time Dashboard**: Secure web interface with authentication & geolocation
- **🆕 Real-Time Alerting System**: Server-Sent Events (SSE) for instant notifications
- **🆕 Automated Incident Response**: Webhook notifications, email alerts, IP blocking
- **IP Geolocation**: Automatic geolocation with dual API fallback (ip-api.com + ipinfo.io)
- **World Map Visualization**: Interactive map showing attack origins
- **Comprehensive Logging**: UTC timestamps, structured JSON logs, PCAP capture
- **Security Hardening**: XSS protection, authentication, security headers
- **Persistent SSH Keys**: No more host key verification errors
- **🆕 Advanced Filtering & Search**: Multi-criteria filtering with date range pickers
- **🆕 Export/Report Generation**: CSV and JSON export with filtering
- **🆕 Mobile Responsive**: Optimized for all device sizes

### 🆕 Real-Time Alerting System
- **Live Alert Notifications**: Real-time alerts via Server-Sent Events (SSE)
- **Alert Types**:
  - High Attack Rate (configurable threshold)
  - Critical Attack Types (SQL Injection, Command Injection, XSS)
  - Suspicious Tools (Metasploit, SQLMap, Hydra)
  - Repeated Attacker (same IP multiple attacks)
  - New Country Detection
- **Alert Severity Levels**: Critical, High, Medium, Info
- **Notification Badges**: Live alert counter in dashboard header
- **Toast Notifications**: Pop-up alerts for critical events
- **Alert Panel**: View and manage all alerts

### 🆕 Automated Incident Response
- **Webhook Notifications**: POST alerts to configured webhook URL
- **Email Notifications**: Framework ready for SMTP integration
- **IP Blocking**: Automatic blocking of malicious IPs (if enabled)
- **Configurable Thresholds**: Customize alert triggers via environment variables

### 🆕 Enhanced Dashboard Features
- **Dark/Light Mode**: Theme toggle with persistent preferences
- **Advanced Search**: Real-time table search
- **Multi-Criteria Filtering**: Filter by date range, service, attack type, country, IP
- **Custom Date Range Pickers**: Native datetime inputs for precise filtering
- **Export Functionality**: Download data as CSV or JSON
- **Real-Time Updates**: Auto-refresh with SSE for alerts
- **Mobile Responsive**: Fully optimized for mobile devices

## 📋 Requirements

### System Requirements
- **Python 3.8+**
- **Operating Systems**: 
  - Linux (Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux, SUSE, Kali Linux)
  - Windows 10/11 (PowerShell 5.1+)
  - macOS
- **Root/sudo privileges** (for binding to privileged ports and PCAP capture on Linux)
- **Available ports**:
  - 2222 (SSH Honeypot)
  - 5001 (Dashboard)
  - 8080 (HTTP Honeypot)
  - 8443 (HTTPS Honeypot)
  - 2121 (FTP Honeypot)
  - 3306 (MySQL Honeypot)

### Python Packages
```bash
pip install paramiko flask requests markupsafe cryptography
```

**Optional but Recommended:**
```bash
pip install flask-socketio  # For enhanced WebSocket support (future)
```

### Optional Dependencies
- `tcpdump` - For full PCAP network capture (Linux/macOS)
- `openssl` - For SSL certificate generation (or uses cryptography module)
- `lsof`, `ss`, or `netstat` - For port checking (Linux)

## 🏗️ Project Structure

```
honeypot-vscode/
├── unified_honeypot.py      # Main honeypot server (SSH, HTTP, HTTPS, FTP, MySQL)
├── app.py                   # Web dashboard with alerting & API endpoints
├── start.sh                 # Linux/macOS startup script
├── run_dashboard.ps1        # Windows PowerShell startup script
├── device_detector.py      # Device/client fingerprinting utility
├── ssh_honeypot.py          # Standalone SSH honeypot (legacy)
├── advanced_honeypot.py     # Advanced honeypot implementation
├── advanced_honeypot_server.py  # Advanced server wrapper
├── config/
│   └── unified_honeypot.json    # Configuration file
├── templates/               # HTML templates
│   ├── unified_dashboard.html   # Main dashboard with all features
│   └── login.html               # Login template
├── tests/                   # Unit tests
├── logs/                    # Log files
│   ├── attacks.json            # Attack log (JSON lines)
│   ├── alerts.json             # Alert log (JSON lines)
│   ├── geocache.json           # IP geolocation cache
│   └── unified_honeypot.log    # Service logs
├── certs/                   # SSL certificates (auto-generated)
├── ssh_keys/                # SSH host keys (auto-generated)
├── pcaps/                   # Network capture files
└── README.md
```

## 🚀 Quick Start

### Linux/macOS

#### 1. Clone the Repository
```bash
git clone https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
cd Team-Avengers-Honeypot
```

#### 2. Set Up Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install paramiko flask requests markupsafe cryptography
```

#### 3. Start the Honeypot System
```bash
# Make script executable
chmod +x start.sh

# Fix line endings if needed (common when cloning on Linux after editing on Windows)
sed -i 's/\r$//' start.sh

# Start the honeypot (requires sudo for privileged ports)
sudo ./start.sh
```

**The script will automatically:**
- ✅ Create required directories (`logs/`, `certs/`, `ssh_keys/`, `pcaps/`, `config/`)
- ✅ Generate persistent SSH host keys
- ✅ Generate SSL certificates for HTTPS
- ✅ Install required Python packages
- ✅ Start all honeypot services
- ✅ Launch the secure dashboard
- ✅ Attempt PCAP capture (if tcpdump is available)

#### 4. Access the Dashboard
- **URL**: http://localhost:5001 (or http://<your-ip>:5001)
- **Username**: `admin`
- **Password**: `honeypot@91771`

### Windows

#### 1. Clone the Repository
```powershell
git clone https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
cd Team-Avengers-Honeypot
```

#### 2. Set Up Python Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install paramiko flask requests markupsafe cryptography
```

#### 3. Start the Honeypot System

**Option A: Using PowerShell Script**
```powershell
.\run_dashboard.ps1
```

**Option B: Manual Start**
```powershell
# Start honeypot server
python unified_honeypot.py

# In another terminal, start dashboard
python app.py
```

#### 4. Access the Dashboard
- **URL**: http://localhost:5001
- **Username**: `admin`
- **Password**: `honeypot@91771`

### Manual Start (All Platforms)

If you prefer to start services manually:

```bash
# Terminal 1: Start honeypot server
python unified_honeypot.py

# Terminal 2: Start dashboard
python app.py
```

## ⚙️ Configuration

### Environment Variables

#### Dashboard Configuration
```bash
# Dashboard credentials
export DASHBOARD_USERNAME="admin"
export DASHBOARD_PASSWORD="honeypot@91771"

# Dashboard port
export FLASK_RUN_PORT=5001

# Log file paths
export ATTACKS_LOG="logs/attacks.json"
export GEOCACHE_FILE="logs/geocache.json"
export ALERTS_LOG="logs/alerts.json"

# Geolocation API
export IP_API_URL="http://ip-api.com/json"
export IP_API_TIMEOUT=3.0
```

#### 🆕 Alert Configuration
```bash
# Alert thresholds
export ALERT_HIGH_RATE=10          # Attacks per minute to trigger alert
export ALERT_REPEATED_IP=5         # Attacks from same IP to trigger alert

# Incident response
export WEBHOOK_URL="https://your-webhook-url.com/alerts"  # Webhook for alerts
export NOTIFY_EMAIL="admin@example.com"                  # Email for notifications
export AUTO_BLOCK_IP="false"                             # Enable IP blocking (true/false)
```

#### Windows PowerShell
```powershell
$env:DASHBOARD_USERNAME="admin"
$env:DASHBOARD_PASSWORD="honeypot@91771"
$env:FLASK_RUN_PORT=5001
$env:ALERT_HIGH_RATE=10
$env:WEBHOOK_URL="https://your-webhook-url.com/alerts"
```

### Honeypot Configuration

Edit `config/unified_honeypot.json`:

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

### Dashboard API

All endpoints require HTTP Basic Authentication (same credentials as dashboard).

#### Get Attacks
**GET `/api/attacks`**
- Returns: JSON object with attack data
- Response:
```json
{
  "count": 150,
  "attacks": [...]
}
```

#### 🆕 Get Alerts
**GET `/api/alerts`**
- Returns: Recent alerts (last 100)
- Response:
```json
{
  "count": 25,
  "alerts": [
    {
      "type": "critical_attack",
      "severity": "critical",
      "message": "Critical attack detected: SQL Injection from 192.168.1.100",
      "timestamp": "2025-01-15T10:30:45.123456+00:00",
      "data": {...}
    }
  ]
}
```

#### 🆕 Real-Time Alert Stream
**GET `/api/alerts/stream`**
- Server-Sent Events (SSE) stream for real-time alerts
- Automatically reconnects on failure
- Usage: Connect with EventSource API

#### 🆕 Filter Attacks
**POST `/api/attacks/filter`**
- Filter attacks by multiple criteria
- Request body:
```json
{
  "start_date": "2025-01-01T00:00:00Z",
  "end_date": "2025-01-31T23:59:59Z",
  "service": "ssh",
  "attack_type": "brute_force",
  "country": "China",
  "ip": "192.168.1.100"
}
```

#### 🆕 Export Attacks
**POST `/api/attacks/export`**
- Export attacks to CSV or JSON
- Request body:
```json
{
  "format": "csv",
  "start_date": "2025-01-01T00:00:00Z",
  "end_date": "2025-01-31T23:59:59Z"
}
```
- Returns: Downloadable file

#### 🆕 Get Statistics
**GET `/api/stats?start_date=2025-01-01&end_date=2025-01-31`**
- Get statistics with optional date range
- Returns: Statistics object

## 🎯 Dashboard Features

### Real-Time Monitoring
- **Live Attack Feed**: Real-time updates of incoming attacks
- **Alert Notifications**: Instant alerts for critical events
- **Auto-Refresh**: Automatic data refresh every 60 seconds

### Advanced Filtering
- **Date Range**: Custom start and end dates
- **Service Filter**: Filter by SSH, HTTP, HTTPS, FTP, MySQL
- **Attack Type**: Filter by attack type
- **Geographic**: Filter by country
- **IP Address**: Search by specific IP

### Data Export
- **CSV Export**: Download filtered data as CSV
- **JSON Export**: Download filtered data as JSON
- **Quick Export**: One-click export from table view

### Visualization
- **Interactive Charts**: Service distribution, attack types, countries
- **World Map**: Geographic visualization of attack sources
- **Statistics Cards**: Key metrics at a glance
- **Attack Table**: Detailed attack log with search

### Mobile Support
- **Responsive Design**: Optimized for all screen sizes
- **Touch-Friendly**: Large buttons and touch targets
- **Mobile Navigation**: Collapsible panels and menus

## 🔒 Security Features

### Dashboard Security
- **HTTP Basic Authentication**: Username/password protection
- **XSS Hardening**: Input sanitization and HTML escaping
- **Security Headers**:
  - Content-Security-Policy (CSP)
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Referrer-Policy: strict-origin-when-cross-origin

### Rate Limiting
- **API Rate Limiting**: 45 requests/minute for geolocation API
- **Thread-Safe**: All operations are thread-safe
- **Cache Management**: LRU cache with TTL (1000 entries, 7 days)

### SSL/TLS
- **Auto-Generated Certificates**: SSL certificates generated automatically
- **HTTPS Support**: Secure HTTPS honeypot service
- **Certificate Persistence**: Certificates saved for reuse

## 📊 Logging & Monitoring

### Log Files
- `logs/attacks.json` - Structured attack data (JSON lines)
- `logs/alerts.json` - Alert log (JSON lines) 🆕
- `logs/geocache.json` - IP geolocation cache
- `logs/unified_honeypot.log` - Service logs

### Attack Detection
- **Tool Detection**: Nmap, Metasploit, Hydra, SQLMap, Nikto, Burp Suite
- **Attack Types**: Brute force, SQL injection, command injection, reconnaissance
- **Device Fingerprinting**: Client version detection and device identification

### IP Geolocation
- **Dual API Support**: Primary (ip-api.com) with fallback (ipinfo.io)
- **Local Caching**: LRU cache with 7-day TTL
- **Rate Limiting**: Automatic rate limit enforcement
- **Graceful Fallback**: Continues operation if APIs fail

## 🎯 Service Details

### SSH Honeypot (Port 2222)
- Full SSH server simulation
- Dynamic password authentication (format: `Honeypot@XXXXX`)
- Interactive shell simulation
- Command execution logging
- Persistent host keys

### HTTP/HTTPS Honeypots (Ports 8080/8443)
- Realistic web server responses
- Login form simulation
- SSL/TLS encryption (HTTPS)
- Request logging and analysis
- Attack pattern detection

### FTP Honeypot (Port 2121)
- Standard FTP protocol simulation
- Authentication tracking
- Connection logging

### MySQL Honeypot (Port 3306)
- Database server simulation
- SQL injection detection
- Connection attempt logging

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Linux
sudo lsof -i :5001  # Check what's using the port
sudo kill -9 <PID>   # Kill the process

# Windows
netstat -ano | findstr :5001
taskkill /PID <PID> /F
```

### Dashboard Not Accessible
- Verify port 5001 is not blocked by firewall
- Check if service started: `ps aux | grep app.py` (Linux) or `Get-Process python` (Windows)
- Review logs: `tail -f logs/unified_honeypot.log`

### Alerts Not Showing
- Check `logs/alerts.json` for alert entries
- Verify SSE connection in browser console
- Check alert thresholds in environment variables

### SSL Certificate Errors
- Certificates are auto-generated on first run
- Check `certs/` directory for certificate files
- Regenerate by deleting `certs/server.crt` and `certs/server.key`

### Geolocation Not Working
- Check internet connection
- Verify API rate limits (45 req/min for ip-api.com)
- Check `logs/geocache.json` for cached entries
- System will fallback to ipinfo.io if primary API fails

## 🧪 Testing

### Run Tests
```bash
pytest tests/
```

### Run Linting
```bash
flake8
```

## 🛡️ Security Considerations

### Important Warnings
- ⚠️ **Never expose the dashboard to the internet** - Use VPN or firewall rules
- ⚠️ **Change default dashboard password** before production use
- ⚠️ **This is a honeypot** - Do not use on production systems
- ⚠️ **Monitor system resources** - Honeypots can attract heavy traffic
- ⚠️ **Review logs regularly** - Check for successful authentication attempts

### Best Practices
- Use strong dashboard credentials
- Regularly rotate SSH passwords (they change on each restart)
- Monitor disk space (PCAP files can be large)
- Keep system and packages updated
- Use firewall rules to restrict dashboard access
- Review attack logs for patterns
- Configure webhook notifications for critical alerts
- Set appropriate alert thresholds

## 📝 Example Usage

### Viewing Alerts
1. Click the 🔔 notification badge in dashboard header
2. Alert panel opens showing recent alerts
3. Click any alert for details

### Filtering Attacks
1. Click "🔍 Filter" button
2. Set filter criteria (date range, service, attack type, etc.)
3. Click "Apply Filters"
4. Table updates with filtered results

### Exporting Data
1. Click "📊 Export" button
2. Select format (CSV/JSON)
3. Optionally set date range
4. Click "Export" to download

### Searching Attacks
1. Type in search box above table
2. Table filters in real-time
3. Works with all table columns

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest` and `flake8`
5. Submit a pull request

## 📄 License

See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built for security research and threat intelligence gathering.

---

**Repository**: https://github.com/Ranaveer9177/Team-Avengers-Honeypot

**Version**: 3.0 - Real-Time Alerting & Advanced Dashboard

**Last Updated**: January 2025
