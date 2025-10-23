# Multi-Service Honeypot System

A sophisticated honeypot system with advanced attack detection, real-time monitoring, and comprehensive logging capabilities.

## Core Components

- **Unified Honeypot** (`unified_honeypot.py`):
  - Multi-service simulation (SSH, HTTP, HTTPS, FTP, MySQL)
  - Advanced attack pattern detection
  - Real-time threat analysis
  - Customizable service responses

- **Service Management** (`service_manager.py`):
  - Dynamic port management
  - Service state monitoring
  - Connection handling
  - Resource management

- **Authentication Handler** (`auth_handler.py`):
  - Custom authentication schemes
  - Credential validation
  - Access control simulation
  - Attack attempt tracking

- **Honeypot Logger** (`honeypot_logger.py`):
  - Structured JSON logging
  - Attack pattern recording
  - Session tracking
  - Event correlation

## Features

- **Multiple Service Simulation:**
  - SSH Server (Port 2222) - Simulates secure shell with key authentication
  - HTTP Server (Port 8080) - Simulates web server with common vulnerabilities
  - HTTPS Server (Port 8443) - SSL/TLS encrypted web server simulation
  - FTP Server (Port 2121) - File transfer protocol simulation
  - MySQL Server (Port 3306) - Database server simulation
  - Dashboard (Port 5001) - Real-time monitoring interface

- **Advanced Attack Detection:**
  - SSH brute force and authentication attempts
  - Web-based attacks (XSS, SQL injection, etc.)
  - Command injection detection
  - Common tool detection (Nmap, Metasploit, etc.)
  - Automated attack pattern recognition
  - Session recording and analysis
  - Device fingerprinting and identification
  - Client software version tracking

- **Dashboard Features:**
  - Live attack visualization
  - Interactive statistics and graphs
  - Attacker geolocation tracking
  - Attack pattern analysis
  - Service-specific monitoring
  - Alert system for suspicious activities

## Requirements

### System Requirements
- Python 3.x
- Linux/Unix operating system
- Root/sudo privileges (for binding to privileged ports)
- Available ports:
  - 2222 (SSH Honeypot)
  - 5001 (Dashboard)
  - 8080 (HTTP Honeypot)
  - 8443 (HTTPS Honeypot)
  - 2121 (FTP Honeypot)
  - 3306 (MySQL Honeypot)

### Python Packages
- paramiko (SSH server simulation)
- flask (Web dashboard)
- Standard library packages:
  - socket (network communication)
  - threading (concurrent operations)
  - json (log formatting)
  - ssl (HTTPS support)

### Required Directories
The following directories will be automatically created by the start script:
- `ssh_keys/` - SSH key storage
- `certs/` - SSL certificates
- `logs/` - Attack and service logs
- `config/` - Service configurations
- `pcaps/` - Network capture files

## Quick Start

1. Clone and enter the repository:
   ```bash
   git clone [repository-url]
   cd honeypot-vscode
   ```

2. Set up Python virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install paramiko flask
   ```

3. Ensure ports are available:
   The following ports must be free (the start script will attempt to free them):
   - 2222 (SSH)
   - 5001 (Dashboard)
   - 8080 (HTTP)
   - 8443 (HTTPS)
   - 2121 (FTP)
   - 3306 (MySQL)

4. Start the honeypot system:
   ```bash
   sudo -E PATH=$PATH ./start.sh
   ```

5. Watch for SSH Password:
   During startup, you'll see a message like:
   ```
   [*] Generated new SSH password: K*ZY\!O*!joyDUtW+2}!w{]?nB6`#ZSq
   ```
   Save this password - it's required for SSH access and changes on every restart.

6. Connect to services:
   - SSH: `ssh -p 2222 admin@<your-ip>`  # Use the generated password
   - Dashboard: http://<your-ip>:5001
   - HTTP: http://<your-ip>:8080
   - HTTPS: https://<your-ip>:8443
   - FTP: `ftp -P 2121 <your-ip>`
   - MySQL: `mysql -h <your-ip> -P 3306`

The start script will automatically:
- Create required directories
- Set appropriate permissions
- Generate SSH keys and SSL certificates
- Install required Python packages
- Start all honeypot services
- Launch the monitoring dashboard
- Display connection information

To stop all services, press Ctrl+C in the terminal where the start script is running.

The startup script will automatically:
- Create and configure necessary directories
- Generate SSH keys and SSL certificates
- Set up proper permissions
- Install required Python packages
- Launch all honeypot services
- Start the monitoring dashboard
- Verify service availability
- Display network connection information

## System Access

The system automatically displays connection information for all services. Access methods:

- **Dashboard Interface:** 
  - Local: http://localhost:5001
  - Remote: http://<your-ip>:5001
  - Real-time monitoring and analytics

- **SSH Honeypot:**
  - Command: `ssh -p 2222 user@<your-ip>`
  - Supports various authentication methods
  - Simulated shell environment

- **Web Services:**
  - HTTP: http://<your-ip>:8080
  - HTTPS: https://<your-ip>:8443
  - Self-signed SSL certificate
  - Various web vulnerability simulations

- **FTP Service:**
  - Command: `ftp -P 2121 <your-ip>`
  - Anonymous and authenticated access
  - File operation logging

- **MySQL Service:**
  - Command: `mysql -h <your-ip> -P 3306`
  - Multiple user privilege levels
  - Query analysis and logging

## Service Details

### SSH Honeypot (Port 2222)
- Full SSH server simulation with dynamic password authentication
- 32-character random password generated on each start
- Password displayed in startup logs for admin access
- Command execution logging and analysis
- Brute force attack detection
- Session recording for analysis
- Username: admin

#### SSH Connection Troubleshooting
Since the honeypot generates new SSH host keys on each start for security, you may encounter a "Host key verification failed" error when reconnecting. To resolve this:

1. Remove the old host key:
   ```bash
   ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[10.0.2.15]:2222"
   ```

2. Then try connecting again:
   ```bash
   ssh -p 2222 admin@10.0.2.15
   ```

The new host key will be automatically accepted on your next connection attempt.

### Web Honeypot (Ports 8080/8443)
- Realistic web server responses
- Common vulnerability simulations
- SSL/TLS encrypted HTTPS support
- Request logging and analysis
- Attack pattern recognition
- File inclusion vulnerability simulation

### FTP Honeypot (Port 2121)
- Standard FTP protocol simulation
- Authentication tracking
- File transfer monitoring
- Directory traversal analysis
- Connection pattern logging

### MySQL Honeypot (Port 3306)
- Database server simulation
- SQL injection detection
- Connection attempt logging
- Query pattern analysis
- User privilege simulation

## Monitoring and Analysis

### Dashboard Features
- Real-time attack visualization
- Interactive statistics
- Geographic attack mapping
- Service-specific metrics
- Custom alert configuration

### Logging System
- Structured logging in JSON format
- Separate logs per service
- Attack pattern correlation
- Automated report generation
- Log rotation and archival

### Directories
- `logs/` - Service and attack logs
- `pcaps/` - Network capture files
- `certs/` - SSL/SSH certificates
- `config/` - Service configurations

## Security Notes

- This is a honeypot system designed for research and monitoring
- Do not use on production systems
- Regularly monitor system resources
- Review logs for genuine attack attempts
- Keep system and packages updated
- PCAP captures for network traffic

## Security Considerations

- Never expose the dashboard (port 5001) to the internet
- Regularly check logs for successful breaches
- Keep the host system updated and secured
- Monitor system resources
- Remove old SSH host keys after honeypot restarts to prevent verification errors

## License

See the [LICENSE](LICENSE) file for details.
