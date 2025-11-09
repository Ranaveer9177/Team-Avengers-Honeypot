import json
import os
import time
import traceback
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, render_template, request, Response, jsonify
from markupsafe import escape

# Flask app
app = Flask(__name__, template_folder='templates')

# Config (override with env vars)
DASHBOARD_USERNAME = os.environ.get('DASHBOARD_USERNAME', 'admin')
DASHBOARD_PASSWORD = os.environ.get('DASHBOARD_PASSWORD', 'honeypot@91771')
GEOCACHE_FILE = os.environ.get('GEOCACHE_FILE', 'logs/geocache.json')
ATTACKS_LOG = os.environ.get('ATTACKS_LOG', 'logs/attacks.json')
FLASK_RUN_PORT = int(os.environ.get('FLASK_RUN_PORT', 5001))
IP_API_URL = os.environ.get('IP_API_URL', 'http://ip-api.com/json')  # ip-api.com simple endpoint
IP_API_TIMEOUT = float(os.environ.get('IP_API_TIMEOUT', 3.0))  # seconds
IPINFO_API_TOKEN = os.environ.get('IPINFO_API_TOKEN', '')  # Optional fallback API

# Simple in-memory cache (loaded from GEOCACHE_FILE on startup)
_geocache = {}

def _load_geocache():
    global _geocache
    try:
        if os.path.exists(GEOCACHE_FILE):
            with open(GEOCACHE_FILE, 'r') as f:
                _geocache = json.load(f)
        else:
            _geocache = {}
    except Exception:
        print("Warning: failed reading geocache, starting with empty cache.")
        _geocache = {}

def _save_geocache():
    try:
        os.makedirs(os.path.dirname(GEOCACHE_FILE) or '.', exist_ok=True)
        with open(GEOCACHE_FILE, 'w') as f:
            json.dump(_geocache, f, indent=2)
    except Exception as e:
        print(f"Warning: failed saving geocache: {e}")

# Load cache at startup
_load_geocache()

def check_auth(username, password):
    """Verify dashboard credentials"""
    return username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD

def authenticate():
    """Return 401 response with authentication challenge"""
    return Response(
        'Login required to access Honeypot Dashboard',
        401,
        {'WWW-Authenticate': 'Basic realm="Honeypot Dashboard"'}
    )

def requires_auth(f):
    """Decorator to require HTTP Basic Authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.after_request
def set_security_headers(response):
    """Add security headers to prevent XSS and other attacks"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://cdn-icons-png.flaticon.com; "
        "connect-src 'self' http://ip-api.com https://ipinfo.io; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers.pop('Server', None)
    return response

def load_attack_data(log_file=ATTACKS_LOG):
    """Read newline-delimited JSON attack log file; returns list of dicts"""
    attacks = []
    if not os.path.exists(log_file):
        return []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    attack = json.loads(line)
                    attacks.append(attack)
                except json.JSONDecodeError:
                    # skip malformed line
                    continue
    except FileNotFoundError:
        return []
    return attacks

def sanitize_string(value, max_length=200):
    """Sanitize string values to prevent XSS attacks"""
    if value is None:
        return ''
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            value = ''
    # Truncate long strings
    if len(value) > max_length:
        value = value[:max_length] + '...'
    return escape(value)

def safe_parse_datetime_obj(timestamp_str):
    """
    Attempt to parse timestamp string and return a datetime (UTC-aware).
    Returns None when parsing fails.
    """
    if not timestamp_str:
        return None
    try:
        if isinstance(timestamp_str, (int, float)):
            return datetime.fromtimestamp(float(timestamp_str), tz=timezone.utc)
        if 'T' in timestamp_str:
            # iso format: ensure timezone
            s = timestamp_str.replace('Z', '+00:00')
            return datetime.fromisoformat(s).astimezone(timezone.utc)
        # fallback common format
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except Exception:
        return None

def safe_format_datetime(dt):
    """Format datetime to readable string, or return 'Unknown'."""
    if not dt:
        return 'Unknown'
    try:
        # Return in local ISO-like format (UTC)
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(dt)

def enrich_with_geo(ip):
    """
    Enrich an IPv4/IPv6 address with full geolocation data.
    Primary: ip-api.com with full fields
    Fallback: ipinfo.io (if IPINFO_API_TOKEN configured)
    Uses local cache to avoid repeated lookups.
    Returns dict with geo fields or None.
    """
    if not ip:
        return None

    # If already cached, return it (check if it has the full structure or old format)
    cached = _geocache.get(ip)
    if cached and 'lat' in cached:
        # Return cached data if it's a full geo dict (has 'lat' key)
        # Old cache entries with just {lat, lon, ts} will be upgraded on next miss
        if 'country' in cached:
            return cached
        # Old format: return None to trigger re-fetch with full data
        elif cached.get('err'):
            # Cached failure - return None
            return None

    # Try ip-api.com first (primary, free, comprehensive)
    try:
        url = f"{IP_API_URL}/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as"
        r = requests.get(url, timeout=IP_API_TIMEOUT)
        data = r.json()
        if data.get('status') == 'success':
            geo_data = {
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'country': data.get('country', 'Unknown'),
                'countryCode': data.get('countryCode', ''),
                'region': data.get('region', ''),
                'regionName': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'zip': data.get('zip', ''),
                'timezone': data.get('timezone', ''),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'as': data.get('as', ''),
                'ts': int(time.time()),
                'source': 'ip-api'
            }
            _geocache[ip] = geo_data
            _save_geocache()
            return geo_data
    except Exception as e:
        print(f"ip-api.com lookup failed for {ip}: {e}")

    # Fallback to ipinfo.io if configured
    if IPINFO_API_TOKEN:
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_TOKEN}"
            r = requests.get(url, timeout=IP_API_TIMEOUT)
            data = r.json()
            if 'loc' in data:
                # Parse lat,lon from "loc" field (format: "lat,lon")
                loc_parts = data.get('loc', ',').split(',')
                lat = float(loc_parts[0]) if len(loc_parts) > 0 and loc_parts[0] else None
                lon = float(loc_parts[1]) if len(loc_parts) > 1 and loc_parts[1] else None

                geo_data = {
                    'lat': lat,
                    'lon': lon,
                    'country': data.get('country', 'Unknown'),
                    'countryCode': data.get('country', ''),
                    'region': data.get('region', ''),
                    'regionName': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('postal', ''),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': '',
                    'ts': int(time.time()),
                    'source': 'ipinfo'
                }
                _geocache[ip] = geo_data
                _save_geocache()
                return geo_data
        except Exception as e:
            print(f"ipinfo.io lookup failed for {ip}: {e}")

    # Both APIs failed - cache failure
    _geocache[ip] = {'lat': None, 'lon': None, 'ts': int(time.time()), 'err': 'All APIs failed'}
    _save_geocache()
    return None

def process_attack_data(attacks):
    """
    Process raw attack dicts, sanitize fields, and enrich with geolocation.
    Returns list of processed attacks ready for templates / JSON.
    Each entry will include:
      - timestamp_str (human readable)
      - timestamp_obj (ISO-ish string in UTC for sorting if needed)
      - ip, service, attack_type, username, auth_method, tools_detected
      - lat, lon (may be None)
    """
    processed = []
    for attack in attacks:
        try:
            # Parse / format timestamp (keep object for sorting)
            raw_ts = attack.get('timestamp', '') or attack.get('time', '')
            ts_obj = safe_parse_datetime_obj(raw_ts)
            ts_str = safe_format_datetime(ts_obj) if ts_obj else (str(raw_ts)[:19] if raw_ts else 'Unknown')

            ip = sanitize_string(attack.get('ip', 'Unknown'))
            # Enrich lat/lon (from cache or API)
            lat, lon = enrich_with_geo(ip)

            processed_attack = {
                'timestamp': ts_str,
                'timestamp_obj': ts_obj.isoformat() if ts_obj else None,
                'ip': ip,
                'device_name': sanitize_string(attack.get('device_name', 'Unknown Device')),
                'service': sanitize_string(attack.get('service', 'unknown')),
                'attack_type': sanitize_string(attack.get('attack_type', 'unknown')),
                'tools_detected': ', '.join(attack.get('tools_detected', [])) if isinstance(attack.get('tools_detected'), list) else sanitize_string(attack.get('tools_detected', 'None detected')),
                'username': sanitize_string(attack.get('username', 'N/A')),
                'auth_method': sanitize_string('Key' if attack.get('key_attempted') else 'Password' if attack.get('password') else 'N/A'),
                'lat': lat,
                'lon': lon
            }
            processed.append(processed_attack)
        except Exception as e:
            print(f"Error processing single attack entry: {e}")
            continue
    return processed

def get_statistics(processed_attacks):
    """
    Build statistics dict from processed attacks (expects sanitized entries).
    """
    stats = {
        'total_attacks': len(processed_attacks),
        'unique_ips': len(set(a.get('ip') for a in processed_attacks)),
        'service_distribution': {},
        'attack_types': {},
        'tools_detected': {},
        'recent_attacks': []
    }

    for a in processed_attacks:
        # Services
        service = a.get('service') or 'unknown'
        stats['service_distribution'][service] = stats['service_distribution'].get(service, 0) + 1

        # Attack types
        attack_type = a.get('attack_type') or 'unknown'
        stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1

        # Tools (if string, try splitting by comma)
        tools_str = a.get('tools_detected') or ''
        if isinstance(tools_str, str) and tools_str:
            for t in [x.strip() for x in tools_str.split(',') if x.strip()]:
                stats['tools_detected'][t] = stats['tools_detected'].get(t, 0) + 1

    # Recent attacks: sort by timestamp_obj if present else stable fallback
    def _sort_key(x):
        try:
            if x.get('timestamp_obj'):
                return datetime.fromisoformat(x['timestamp_obj'])
        except Exception:
            pass
        return datetime.min

    stats['recent_attacks'] = sorted(processed_attacks, key=_sort_key, reverse=True)[:50]
    return stats

@app.route('/')
@requires_auth
def dashboard():
    """Main dashboard route - renders the HTML dashboard (map + charts + table)."""
    try:
        raw_attacks = load_attack_data()
        processed = process_attack_data(raw_attacks)
        statistics = get_statistics(processed)

        # Sanitize statistic keys for template safety (keys are already strings)
        sanitized_stats = {
            'total_attacks': statistics['total_attacks'],
            'unique_ips': statistics['unique_ips'],
            'service_distribution': {str(k): v for k, v in statistics['service_distribution'].items()},
            'attack_types': {str(k): v for k, v in statistics['attack_types'].items()},
            'tools_detected': {str(k): v for k, v in statistics['tools_detected'].items()},
            # include recent_attacks (already sanitized)
            'recent_attacks': statistics['recent_attacks']
        }

        return render_template('unified_dashboard.html', statistics=sanitized_stats, attacks=processed)
    except Exception as e:
        error_msg = f"Error loading dashboard: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        return f"<h1>Internal Server Error</h1><p>{escape(error_msg)}</p><pre>{escape(traceback.format_exc())}</pre>", 500

@app.route('/api/attacks')
@requires_auth
def api_attacks():
    """
    Return JSON list of processed/enriched attacks for front-end (map/chart).
    Useful for dynamic polling / websocket fallback.
    """
    try:
        raw = load_attack_data()
        processed = process_attack_data(raw)
        # We return most recent 500 to limit payload size
        return jsonify({'count': len(processed), 'attacks': processed[:500]})
    except Exception as e:
        print(f"API error: {e}")
        return jsonify({'error': 'Failed to load attacks'}), 500

if __name__ == '__main__':
    # Ensure directories exist
    try:
        os.makedirs(os.path.dirname(ATTACKS_LOG) or 'logs', exist_ok=True)
    except Exception:
        pass

    # Run app
    print(f"Starting dashboard on port {FLASK_RUN_PORT}")
    print(f"Attack logs: {os.path.abspath(ATTACKS_LOG)}")
    app.run(host='0.0.0.0', port=FLASK_RUN_PORT, debug=False)

