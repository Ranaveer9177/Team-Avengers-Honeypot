# Changelog

All notable changes to the Multi-Service Honeypot System will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-05-05

### Added
- **Tabbed Dashboard UI**: Sidebar navigation with Dashboard, Attack Logs, and Connections tabs
- **Dark Theme**: Full glassmorphism dark-themed interface with Inter/JetBrains Mono fonts
- **Attack Logs View**: Paginated table with real-time search, sortable columns, expandable row details
- **Connections View**: Top attackers leaderboard, country/ISP analysis, attack timeline chart
- **CSV Export**: One-click export from logs tab
- **JSON Export**: Full data export via export modal
- **Reset with Backup**: Dashboard reset creates timestamped backups before clearing data
- **Session-Based Auth**: Flask sessions with cookies (no credentials in page source)
- **Batch Geocache Writes**: `_maybe_save_geocache()` batches writes every 10 lookups
- **Thread-Safe Geocache**: Added `threading.Lock()` to all `_geocache` operations
- **IP Validation**: `/api/attacks/filter` validates IP format using `ipaddress` module
- **Safe Print**: Unicode-safe console output for Windows terminals
- **Separate Timeouts**: SSH uses persistent timeout (None), FTP/MySQL/HTTP use 30s

### Changed
- Dashboard redesigned from flat layout to sidebar + tabbed architecture
- FTP handler now uses multi-step protocol loop (USER → 331 → PASS → 530)
- Rate limiter `time.sleep()` moved outside lock to prevent thread blocking
- Bare `except:` clauses replaced with `except Exception:` throughout
- `start.sh` permissions: `chmod 700` for ssh_keys/certs, `chmod 755` for logs/config/pcaps
- Content-Security-Policy updated for Chart.js, Leaflet, and CartoDB tile servers

### Removed
- `ssh_honeypot.py` — old SSH-only honeypot (superseded by `unified_honeypot.py`)
- `ssh_dashboard.py` — old SSH dashboard (superseded by `app.py`)
- `app_test.py` — dummy data test dashboard (no longer needed)
- `advanced_honeypot.py` — abandoned experimental honeypot
- `advanced_honeypot_server.py` — abandoned server wrapper
- Credentials removed from frontend JavaScript (`_DASH_USER`, `_DASH_PASS`)

### Fixed
- BUG-001: `UnicodeEncodeError` on Windows terminals with emoji characters
- BUG-002: Race condition in `_geocache` OrderedDict (thread-safe with Lock)
- BUG-003: `connection_timeout = None` applied to FTP/MySQL/HTTP (now uses 30s)
- BUG-004: Bare `except:` clauses swallowing KeyboardInterrupt/SystemExit
- BUG-005: `_api_lock` blocking all threads during rate-limit sleep
- BUG-006: FTP handler single `recv()` not handling multi-step protocol
- BUG-007: No IP validation on `/api/attacks/filter` endpoint
- BUG-008: Dashboard credentials exposed in page source JavaScript
- BUG-010: `chmod 777` on sensitive directories (ssh_keys, certs)
- BUG-012: Geocache writing to disk on every single IP lookup
- Test: `test_http_user_agent_detection` — payload now includes User-Agent header
- Test: `test_fake_filesystem_file_reading` — fixed root node traversal
- Test: `test_tool_detection` — fixed Windows file-lock cleanup

### Security
- Session-based authentication replaces Basic Auth in API calls from dashboard JS
- IP filter input validation prevents probe attacks
- Sensitive directories restricted to owner-only access

## [3.0.0] - 2025-01-15

### Added
- Interactive Boot Menu with Encrypted Honeypot option
- Auto-generated secure SSH passwords (format: honeypot@XXXX)
- Real-Time Alerting System with Server-Sent Events (SSE)
- Automated Incident Response (webhooks, email framework, IP blocking)
- Advanced Filtering & Search with date range pickers
- Export/Report Generation (CSV and JSON)
- Mobile responsive design

## [2.0.0] - 2024-06-01

### Added
- FTP honeypot service handler
- MySQL honeypot service handler
- Windows PowerShell startup script
- Device detection with DeviceDetector class
- Comprehensive test suite

## [1.0.0] - 2024-01-15

### Added
- Initial release
- Multi-service honeypot (SSH, HTTP, HTTPS)
- Web dashboard with authentication
- IP geolocation with caching
- Interactive world map visualization
- Attack pattern and tool detection
- PCAP capture support
- Persistent SSH host keys

---

For older releases, see the [GitHub releases page](https://github.com/Ranaveer9177/Team-Avengers-Honeypot/releases).
