# Honeypot API Documentation

This document describes the API endpoints available in the honeypot dashboard.

## Authentication

The dashboard uses **session-based form login** for browser access and **HTTP Basic Auth** as a fallback for API clients (curl, scripts).

**Default Username:** `admin`

**Password:** Auto-generated fresh on every startup (8 characters: letters, digits, at least 1 special character).
- Always printed in console when the server starts
- Changes on every restart
- To use a fixed password, set the `DASHBOARD_PASSWORD` env var
```bash
export DASHBOARD_USERNAME="your_username"
export DASHBOARD_PASSWORD="your_password"
```

> **Note (v4.1):** Browser access is now handled via a login form at `/login`. API endpoints still accept HTTP Basic Auth for scripts and automation.

## Base URL

```
http://localhost:5001
```

## Endpoints

### GET/POST /login

**Description:** Login page. Renders the login form on GET, authenticates on POST.

**Authentication:** None required (this IS the authentication endpoint)

**POST Parameters (form data):**
- `username` — Dashboard username
- `password` — Dashboard password

**Status Codes:**
- `200 OK` — Login form rendered (GET) or invalid credentials (POST)
- `302 Found` — Successful login, redirects to `/`

---

### GET /logout

**Description:** Clears the session and redirects to the login page.

**Authentication:** None required

**Status Codes:**
- `302 Found` — Redirects to `/login`

---

### GET /

**Description:** Main dashboard HTML page with tabbed navigation (Dashboard, Attack Logs, Connections).

**Authentication:** Required (session or HTTP Basic Auth)

**Response:** HTML page with:
- Dashboard tab: Stat cards, doughnut charts, interactive world map
- Attack Logs tab: Paginated table with search, sort, filter, and CSV export
- Connections tab: Top attackers, country/ISP analysis, attack timeline

**Status Codes:**
- `200 OK` — Success
- `302 Found` — Not authenticated, redirects to `/login`

---

### GET /api/attacks

**Description:** Retrieve attack data in JSON format.

**Authentication:** Required

**Response:**
```json
{
  "count": 150,
  "attacks": [
    {
      "timestamp": "2026-05-05 08:12:33",
      "timestamp_obj": "2026-05-05T08:12:33+00:00",
      "ip": "185.220.101.34",
      "device_name": "Linux Server",
      "service": "ssh",
      "attack_type": "Brute Force",
      "tools_detected": "hydra",
      "username": "root",
      "auth_method": "Password",
      "city": "Brandenburg",
      "country": "Germany",
      "isp": "Tor Exit Node",
      "lat": 52.41,
      "lon": 12.53
    }
  ]
}
```

**Example:**
```bash
curl -u admin:'YOUR_PASSWORD' http://localhost:5001/api/attacks
```

---

### GET /api/alerts

**Description:** Get recent alerts (last 100).

**Authentication:** Required

**Response:**
```json
{
  "count": 25,
  "alerts": [
    {
      "type": "critical_attack",
      "severity": "critical",
      "message": "Critical attack detected: SQL Injection from 45.33.32.156",
      "timestamp": "2026-05-05T08:15:41+00:00",
      "data": {}
    }
  ]
}
```

---

### GET /api/alerts/stream

**Description:** Server-Sent Events (SSE) stream for real-time alerts.

**Authentication:** Required

**Usage:**
```javascript
const source = new EventSource('/api/alerts/stream');
source.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```

---

### POST /api/attacks/filter

**Description:** Filter attacks by multiple criteria. IP addresses are validated using the `ipaddress` module.

**Authentication:** Required

**Request Body:**
```json
{
  "start_date": "2026-05-01T00:00:00Z",
  "end_date": "2026-05-31T23:59:59Z",
  "service": "ssh",
  "attack_type": "Brute Force",
  "country": "Germany",
  "ip": "185.220.101.34"
}
```

**Response:**
```json
{
  "count": 5,
  "attacks": [...]
}
```

**Error (invalid IP):**
```json
{
  "error": "Invalid IP address format"
}
```

---

### POST /api/attacks/export

**Description:** Export attacks to CSV or JSON format.

**Authentication:** Required

**Request Body:**
```json
{
  "format": "csv",
  "start_date": "2026-05-01T00:00:00Z",
  "end_date": "2026-05-31T23:59:59Z"
}
```

**Response:** Downloadable file (CSV or JSON).

---

### POST /api/reset

**Description:** Reset the dashboard — creates a timestamped backup of all logs, then clears the data.

**Authentication:** Required

**Response:**
```json
{
  "success": true,
  "message": "Dashboard reset successfully",
  "backup_file": "logs/backups/attacks_backup_20260505_112507.txt"
}
```

---

### GET /api/stats

**Description:** Get statistics with optional date range.

**Query Parameters:**
- `start_date` (optional): ISO date string
- `end_date` (optional): ISO date string

**Response:**
```json
{
  "total_attacks": 150,
  "unique_ips": 42,
  "service_distribution": {"ssh": 80, "http": 45, "ftp": 25},
  "attack_types": {"Brute Force": 90, "SQL Injection": 30},
  "top_countries": [["Germany", 40], ["USA", 30]],
  "top_isps": [["Tor Exit Node", 15], ["DigitalOcean", 10]]
}
```

## Attack Types

| Attack Type | Description |
|---|---|
| `password_auth` | SSH password authentication attempt |
| `key_auth` | SSH key authentication attempt |
| `brute_force_web` | Web application brute force |
| `ftp_brute_force` | FTP brute force attempt |
| `mysql_connection_attempt` | MySQL connection attempt |
| `sql_injection` | SQL injection attempt |
| `command_injection` | Command injection attempt |
| `reconnaissance` | Reconnaissance activity |
| `xss` | Cross-site scripting attempt |

## Tools Detected

| Tool | Description |
|---|---|
| `nmap` | Network scanner |
| `metasploit` | Exploitation framework |
| `hydra` | Password cracker |
| `medusa` | Parallel login brute-forcer |
| `burpsuite` | Web security testing tool |
| `sqlmap` | SQL injection tool |
| `nikto` | Web server scanner |

## Rate Limiting

- Geolocation API: 45 requests/minute (thread-safe, non-blocking)
- Rate limit sleep happens outside the lock (v4.0 fix)
- Geocache batches disk writes every 10 new entries

## Security

1. **Change default credentials** before production use
2. **Use HTTPS** — deploy behind a reverse proxy (nginx)
3. **Restrict access** — firewall rules for port 5001
4. **VPN access** — never expose dashboard to public internet

---

**Version:** 4.1 | **Last Updated:** June 2026
