# Multi-Service Honeypot System

A sophisticated honeypot system with advanced attack detection, real-time monitoring, comprehensive logging, and security hardening.

## 🚀 Features

### Core Capabilities
- **Multi-Service Simulation**: SSH, HTTP, HTTPS, FTP, MySQL
- **Advanced Attack Detection**: Pattern recognition, tool detection, device fingerprinting
- **Real-Time Dashboard**: Secure web interface with authentication
- **Comprehensive Logging**: UTC timestamps, structured JSON logs, PCAP capture
- **Security Hardening**: XSS protection, authentication, security headers
- **Persistent SSH Keys**: No more host key verification errors
- **CI/CD Integration**: Automated testing and linting

## 📋 Requirements

### System Requirements
- Python 3.8+
- Linux/Unix operating system (Windows with WSL supported)
- Root/sudo privileges (for binding to privileged ports and PCAP capture)
- Available ports:
  - 2222 (SSH Honeypot)
  - 5001 (Dashboard)
  - 8080 (HTTP Honeypot)
  - 8443 (HTTPS Honeypot)
  - 2121 (FTP Honeypot)
  - 3306 (MySQL Honeypot)

### Python Packages
```bash
pip install paramiko flask
```

### Optional Dependencies
- `tcpdump` - For full PCAP network capture (automatically attempted, logs warning if unavailable)

## 🏗️ Project Structure

```
honeypot-vscode/
├── unified_honeypot.py      # Main honeypot server
├── unified_dashboard.py     # Web dashboard with authentication
├── start.sh                 # Startup script
├── config/
│   └── unified_honeypot.json
├── templates/               # HTML templates
│   ├── unified_dashboard.html
│   └── login.html
├── tests/                   # Unit tests
│   ├── test_config.py
│   └── test_dashboard.py
├── .github/workflows/       # CI/CD
│   └── ci.yml
└── README.md
```

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
cd Team-Avengers-Honeypot
```

### 2. Set Up Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install paramiko flask
```

### 3. Start the Honeypot System
```bash
sudo ./start.sh
```

The script will automatically:
- ✅ Create required directories (`logs/`, `certs/`, `ssh_keys/`, `pcaps/`, `config/`)
- ✅ Generate persistent SSH host keys (reused across restarts)
- ✅ Generate SSL certificates for HTTPS
- ✅ Install required Python packages
- ✅ Start all honeypot services
- ✅ Launch the secure dashboard
- ✅ Attempt PCAP capture (if tcpdump is available)

### 4. Access the Dashboard
- **URL**: http://localhost:5001 (or http://<your-ip>:5001)
- **Username**: `admin`
- **Password**: `honeypot@91771`

> **Note**: You can change credentials via environment variables:
> ```bash
> export DASHBOARD_USERNAME="your_username"
> export DASHBOARD_PASSWORD="your_password"
> ```

### 5. SSH Access
During startup, a random SSH password is generated:
```
[!] IMPORTANT: New SSH Password Generated
[!] Username: admin
[!] Password: Honeypot@12345
```

Connect using:
```bash
ssh -p 2222 admin@<your-ip>
# Use the password shown during startup
```

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

### SSH Key Persistence
- SSH host keys are persisted across restarts
- No more "Host key verification failed" errors
- Keys automatically generated on first run
- Stored in `ssh_keys/server.key`

### Service Banners
- Consistent service identification:
  - SSH: `SSH-2.0-OpenSSH_7.4`
  - HTTP/HTTPS: `Apache/2.4.41 (Ubuntu)`
- Configurable via `config/unified_honeypot.json`

## 📊 Instrumentation & Logging

### Timestamps
- All logs use **UTC ISO8601 format** for consistency
- Example: `2024-01-15T10:30:45.123456+00:00`

### Log Files
- `logs/attacks.json` - Structured attack data (JSON lines)
- `logs/unified_honeypot.log` - Service logs
- All attack data includes: IP, timestamp, service, attack type, tools detected

### PCAP Capture
- **Initial Payload Capture**: First 512 bytes of each connection saved to `pcaps/`
- **Full PCAP Capture**: Automatic tcpdump capture (if available)
- Files saved as: `pcaps/unified_YYYYMMDDTHHMMSSZ.pcap`
- Configurable via `config/unified_honeypot.json`:
  ```json
  {
    "pcap_enabled": true,
    "pcap_dir": "pcaps",
    "initial_payload_max_bytes": 512
  }
  ```

### Attack Detection
- **Tool Detection**: Nmap, Metasploit, Hydra, SQLMap, Nikto, Burp Suite
- **Attack Types**: Brute force, SQL injection, command injection, reconnaissance
- **Device Fingerprinting**: Client version detection and device identification

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

### Dashboard (Port 5001)
- Real-time attack visualization
- Interactive statistics and charts
- Service-specific metrics
- Attack pattern analysis
- **Protected with authentication**

## 🧪 Testing

### Run Tests
```bash
pytest tests/
```

### Run Linting
```bash
flake8
```

### CI/CD
GitHub Actions automatically runs:
- Flake8 linting
- Pytest unit tests

## ⚙️ Configuration

Edit `config/unified_honeypot.json` to customize:

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

## 🔧 Troubleshooting

### SSH Host Key Verification Failed
This should no longer occur as keys are persisted. If it does:
```bash
ssh-keygen -R "[<ip>]:2222"
```

### Port Already in Use
The start script attempts to free ports automatically. If issues persist:
```bash
sudo lsof -i :2222  # Check what's using the port
sudo kill -9 <PID>  # Kill the process
```

### PCAP Capture Not Working
- Ensure `tcpdump` is installed: `sudo apt-get install tcpdump`
- Check permissions: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump`
- Check logs for warnings

### Dashboard Not Accessible
- Verify port 5001 is not blocked by firewall
- Check if service started: `ps aux | grep unified_dashboard`
- Review logs: `tail -f logs/unified_honeypot.log`

## 📝 Logging Examples

### Attack Log Entry (logs/attacks.json)
```json
{
  "ip": "192.168.1.100",
  "timestamp": "2024-01-15T10:30:45.123456+00:00",
  "service": "ssh",
  "attack_type": "password_auth",
  "username": "admin",
  "password": "test123",
  "tools_detected": ["hydra"],
  "device_name": "Unknown Device"
}
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
