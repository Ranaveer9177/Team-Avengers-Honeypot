# SSH Honeypot (Paramiko)

A simple SSH honeypot using Paramiko that accepts all password logins and logs credentials and commands. It presents a minimal fake shell to keep attackers engaged and records activity to JSON lines in `honeypot_logs/`.

## Features
- Accepts any password (also logs attempted public key fingerprint)
- Logs to JSONL by day: `attacks_YYYY-MM-DD.json` and `commands_YYYY-MM-DD.json`
- Mimics a few common commands: `ls`, `pwd`, `whoami`, `uname`, `cat /etc/passwd`, `id`
- Pretends to be `OpenSSH_8.2p1` on Ubuntu 20.04
- Real-time dashboard (Flask + SocketIO) with leaderboard and alerts
- Optional GeoIP location lookup (MaxMind GeoLite2)

## Requirements
- Python 3.9+
- Windows 10/11 or Linux

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run the SSH Honeypot
```powershell
python .\honeypot.py
```
Expected output:
```
[*] SSH Honeypot listening on 0.0.0.0:2222
[*] Logs saved to honeypot_logs
```

## Run the Dashboard
In a separate terminal (same venv):
```powershell
python .\app.py
```
Open `http://localhost:5000` in your browser.

## Test from another machine
```bash
ssh -p 2222 whatever@<your_ip>
# enter any password, try commands
```

## Files
- `honeypot.py` — SSH honeypot server
- `app.py` — Flask-SocketIO dashboard (REST + WebSocket)
- `templates/dashboard.html` — dashboard UI
- `server.key` — auto-generated RSA host key on first run
- `honeypot_logs/` — JSONL logs and a text log `ssh_honeypot.log`

## Optional: Faster SocketIO
Install an async backend (choose one):
```powershell
pip install eventlet
# or
pip install gevent gevent-websocket
```

If using eventlet, run dashboard with:
```powershell
python .\app.py
```
(Flask-SocketIO will auto-detect eventlet/gevent.)

## Optional: GeoIP Setup
1) Create a free MaxMind account and download `GeoLite2-City.mmdb`.
2) Place the file next to `app.py` (or provide a full path when creating `GeoIPTracker`).
3) GeoIP is optional; without the DB, location fields are `null`.

## Notes
- This is a honeypot: do not run on production hosts.
- Prefer running inside a VM or an isolated network segment.
- Only a tiny subset of commands are emulated; others return `command not found`.
- Consider firewalling so only intended external sources can connect to port 2222.

## Extending
- Implement richer shell emulation and fake filesystem.
- Add persistence for aggregated stats (SQLite) and historical graphs.
- Stream events to SIEM (e.g., Kafka/Elastic) from `notify_new_attack()`.
