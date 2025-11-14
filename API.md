# Honeypot API Documentation

This document describes the API endpoints available in the honeypot dashboard.

## Authentication

All API endpoints require HTTP Basic Authentication.

**Default Credentials:**
- Username: `admin`
- Password: `honeypot@91771`

**Environment Variables:**
```bash
export DASHBOARD_USERNAME="your_username"
export DASHBOARD_PASSWORD="your_password"
```

## Base URL

```
http://localhost:5001
```

Or use your server's IP address:
```
http://<your-ip>:5001
```

## Endpoints

### GET /

**Description:** Main dashboard HTML page

**Authentication:** Required (HTTP Basic Auth)

**Response:** HTML page with:
- Attack statistics
- Service distribution charts
- Interactive world map
- Recent attacks table

**Status Codes:**
- `200 OK` - Success
- `401 Unauthorized` - Invalid credentials
- `500 Internal Server Error` - Server error

---

### GET /api/attacks

**Description:** Retrieve attack data in JSON format

**Authentication:** Required (HTTP Basic Auth)

**Response Format:**
```json
{
  "count": 150,
  "attacks": [
    {
      "timestamp": "2024-01-15 10:30:45",
      "timestamp_obj": "2024-01-15T10:30:45.123456+00:00",
      "ip": "192.168.1.100",
      "device_name": "OpenSSH 8.2 (Linux)",
      "service": "ssh",
      "attack_type": "password_auth",
      "tools_detected": "hydra, nmap",
      "username": "admin",
      "auth_method": "Password",
      "lat": 37.7749,
      "lon": -122.4194
    }
  ]
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `count` | integer | Total number of attacks |
| `attacks` | array | Array of attack objects (max 500) |
| `timestamp` | string | Human-readable timestamp (UTC) |
| `timestamp_obj` | string | ISO format timestamp for sorting |
| `ip` | string | Source IP address |
| `device_name` | string | Detected device/client name |
| `service` | string | Target service (ssh, http, https, ftp, mysql) |
| `attack_type` | string | Type of attack detected |
| `tools_detected` | string | Comma-separated list of detected tools |
| `username` | string | Username used in attack (if applicable) |
| `auth_method` | string | Authentication method (Password/Key) |
| `lat` | float | Latitude (null if geolocation unavailable) |
| `lon` | float | Longitude (null if geolocation unavailable) |

**Status Codes:**
- `200 OK` - Success
- `401 Unauthorized` - Invalid credentials
- `500 Internal Server Error` - Failed to load attacks

**Example Request (curl):**
```bash
curl -u admin:honeypot@91771 http://localhost:5001/api/attacks
```

**Example Request (Python):**
```python
import requests
from requests.auth import HTTPBasicAuth

response = requests.get(
    'http://localhost:5001/api/attacks',
    auth=HTTPBasicAuth('admin', 'honeypot@91771')
)

if response.status_code == 200:
    data = response.json()
    print(f"Total attacks: {data['count']}")
    for attack in data['attacks']:
        print(f"{attack['timestamp']} - {attack['ip']} - {attack['service']}")
```

**Example Request (JavaScript):**
```javascript
const username = 'admin';
const password = 'honeypot@91771';
const url = 'http://localhost:5001/api/attacks';

fetch(url, {
  headers: {
    'Authorization': 'Basic ' + btoa(username + ':' + password)
  }
})
.then(response => response.json())
.then(data => {
  console.log(`Total attacks: ${data.count}`);
  data.attacks.forEach(attack => {
    console.log(`${attack.timestamp} - ${attack.ip} - ${attack.service}`);
  });
});
```

## Attack Types

The system detects various attack types:

| Attack Type | Description |
|-------------|-------------|
| `password_auth` | SSH password authentication attempt |
| `key_auth` | SSH key authentication attempt |
| `brute_force_web` | Web application brute force |
| `ftp_brute_force` | FTP brute force attempt |
| `mysql_connection_attempt` | MySQL connection attempt |
| `web_request` | Generic web request |
| `sql_injection` | SQL injection attempt |
| `command_injection` | Command injection attempt |
| `reconnaissance` | Reconnaissance activity |

## Tools Detected

The system can identify these penetration testing tools:

- **nmap** - Network scanner
- **metasploit** - Exploitation framework
- **hydra** - Password cracker
- **medusa** - Parallel login brute-forcer
- **burpsuite** - Web security testing tool
- **sqlmap** - SQL injection tool
- **nikto** - Web server scanner

## Data Filtering

The API currently returns the most recent 500 attacks. For production use, consider implementing:

- Pagination parameters (`?page=1&limit=50`)
- Date range filtering (`?start_date=2024-01-01&end_date=2024-01-31`)
- Service filtering (`?service=ssh`)
- IP filtering (`?ip=192.168.1.100`)

## Rate Limiting

Currently no rate limiting is implemented. For production:

- Implement rate limiting (e.g., 100 requests/minute)
- Use API tokens instead of Basic Auth
- Add request logging and monitoring

## Security Considerations

### Best Practices

1. **Change Default Credentials**
   ```bash
   export DASHBOARD_USERNAME="your_secure_username"
   export DASHBOARD_PASSWORD="your_strong_password"
   ```

2. **Use HTTPS in Production**
   - Deploy behind a reverse proxy (nginx, Apache)
   - Use SSL/TLS certificates
   - Never expose the dashboard directly to the internet

3. **Firewall Rules**
   ```bash
   # Allow only from specific IP
   ufw allow from 192.168.1.0/24 to any port 5001
   ```

4. **VPN Access**
   - Use VPN for remote dashboard access
   - Never expose port 5001 to the public internet

5. **API Token Authentication** (Future Enhancement)
   - Implement JWT or OAuth2
   - Use API keys with expiration
   - Add role-based access control

## Integration Examples

### SIEM Integration

```python
# Example: Send attacks to SIEM system
import requests
from requests.auth import HTTPBasicAuth

def fetch_and_forward_attacks(siem_url, siem_token):
    # Fetch from honeypot
    response = requests.get(
        'http://localhost:5001/api/attacks',
        auth=HTTPBasicAuth('admin', 'honeypot@91771')
    )
    
    if response.status_code == 200:
        attacks = response.json()['attacks']
        
        # Forward to SIEM
        for attack in attacks:
            requests.post(
                siem_url,
                headers={'Authorization': f'Bearer {siem_token}'},
                json=attack
            )
```

### Automated Alerting

```python
# Example: Send alerts for specific attacks
import requests
from requests.auth import HTTPBasicAuth
import smtplib
from email.mime.text import MIMEText

def check_for_critical_attacks():
    response = requests.get(
        'http://localhost:5001/api/attacks',
        auth=HTTPBasicAuth('admin', 'honeypot@91771')
    )
    
    if response.status_code == 200:
        attacks = response.json()['attacks']
        
        # Filter critical attacks
        critical = [a for a in attacks if 'metasploit' in a.get('tools_detected', '')]
        
        if critical:
            send_alert_email(critical)

def send_alert_email(attacks):
    msg = MIMEText(f"Critical attacks detected: {len(attacks)}")
    msg['Subject'] = 'Honeypot Alert'
    msg['From'] = 'honeypot@example.com'
    msg['To'] = 'admin@example.com'
    
    # Send email (configure your SMTP server)
    # ...
```

### Dashboard Widget

```html
<!-- Example: Simple dashboard widget -->
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Stats</title>
    <script>
        async function updateStats() {
            const response = await fetch('http://localhost:5001/api/attacks', {
                headers: {
                    'Authorization': 'Basic ' + btoa('admin:honeypot@91771')
                }
            });
            
            const data = await response.json();
            
            document.getElementById('total').textContent = data.count;
            document.getElementById('recent').textContent = data.attacks.length;
        }
        
        // Update every 30 seconds
        setInterval(updateStats, 30000);
        updateStats();
    </script>
</head>
<body>
    <h1>Honeypot Statistics</h1>
    <p>Total Attacks: <span id="total">0</span></p>
    <p>Recent Attacks: <span id="recent">0</span></p>
</body>
</html>
```

## Error Handling

All endpoints return appropriate HTTP status codes:

| Status Code | Meaning |
|-------------|---------|
| 200 | Success |
| 401 | Authentication required or invalid credentials |
| 500 | Internal server error |

Error responses include a message:
```json
{
  "error": "Failed to load attacks"
}
```

## Future Enhancements

Planned API improvements:

- [ ] Pagination support
- [ ] Advanced filtering options
- [ ] Real-time WebSocket updates
- [ ] Export formats (CSV, PDF)
- [ ] Attack statistics endpoint
- [ ] Service status endpoint
- [ ] Configuration endpoint (read-only)
- [ ] API token authentication
- [ ] Rate limiting
- [ ] API versioning (/api/v1/)

## Support

For API questions or issues:
- Create an issue on GitHub
- Check the documentation
- Review example code in `examples/` directory

## License

This API is part of the Multi-Service Honeypot System. See LICENSE file for details.
