import json
import os
import time
import traceback
import logging
import threading
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import OrderedDict, deque
from queue import Queue

import requests
from flask import Flask, render_template, request, Response, jsonify, stream_with_context, url_for
from markupsafe import escape

# Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Config (override with env vars)
DASHBOARD_USERNAME = os.environ.get('DASHBOARD_USERNAME', 'admin')
DASHBOARD_PASSWORD = os.environ.get('DASHBOARD_PASSWORD', 'honeypot@91771')
GEOCACHE_FILE = os.environ.get('GEOCACHE_FILE', 'logs/geocache.json')
ATTACKS_LOG = os.environ.get('ATTACKS_LOG', 'logs/attacks.json')
FLASK_RUN_PORT = int(os.environ.get('FLASK_RUN_PORT', 5001))
IP_API_URL = os.environ.get('IP_API_URL', 'http://ip-api.com/json')  # ip-api.com simple endpoint
IP_API_TIMEOUT = float(os.environ.get('IP_API_TIMEOUT', 3.0))  # seconds

# API Rate Limiting: ip-api.com allows 45 requests/minute
API_RATE_LIMIT = 45  # requests per minute
API_RATE_WINDOW = 60  # seconds
_api_request_times = []  # List of timestamps for rate limiting
_api_lock = threading.Lock()  # Thread-safe rate limiting

# LRU Cache with TTL: Max 1000 entries, 7 days expiration
MAX_CACHE_SIZE = 1000
CACHE_TTL_DAYS = 7
_geocache = OrderedDict()  # OrderedDict for LRU behavior
_last_cleanup_time = 0  # Track last cleanup time
CLEANUP_INTERVAL = 300  # Cleanup every 5 minutes (300 seconds)

# Real-Time Alerting System
ALERT_QUEUE = Queue()  # Thread-safe queue for alerts
ALERT_SUBSCRIBERS = []  # List of SSE subscribers
ALERT_LOCK = threading.Lock()
ALERTS_LOG = os.environ.get('ALERTS_LOG', 'logs/alerts.json')

# Alert Thresholds (configurable)
ALERT_THRESHOLDS = {
    'high_attack_rate': int(os.environ.get('ALERT_HIGH_RATE', 10)),  # attacks per minute
    'critical_attack_types': ['SQL Injection', 'Command Injection', 'XSS'],
    'suspicious_tools': ['metasploit', 'sqlmap', 'hydra'],
    'repeated_attacker': int(os.environ.get('ALERT_REPEATED_IP', 5)),  # attacks from same IP
    'new_country': True,  # Alert on attacks from new countries
}

# Incident Response Actions
INCIDENT_RESPONSES = {
    'block_ip': os.environ.get('AUTO_BLOCK_IP', 'false').lower() == 'true',
    'notify_email': os.environ.get('NOTIFY_EMAIL', ''),
    'webhook_url': os.environ.get('WEBHOOK_URL', ''),
}

# Track recent attacks for alerting
_recent_attacks = deque(maxlen=1000)  # Last 1000 attacks
_attack_counts = {}  # IP -> count in last minute
_known_countries = set()  # Track known countries

def _load_geocache():
    """Load geocache from file, filtering expired entries and limiting size"""
    global _geocache
    try:
        if os.path.exists(GEOCACHE_FILE):
            with open(GEOCACHE_FILE, 'r') as f:
                raw_cache = json.load(f)
                # Convert to OrderedDict and filter expired entries
                _geocache = OrderedDict()
                current_time = int(time.time())
                ttl_seconds = CACHE_TTL_DAYS * 24 * 60 * 60
                
                for ip, data in raw_cache.items():
                    cache_time = data.get('ts', 0)
                    if current_time - cache_time < ttl_seconds:
                        _geocache[ip] = data
                    # Limit size during load
                    if len(_geocache) >= MAX_CACHE_SIZE:
                        break
                
                logger.info(f"Loaded {len(_geocache)} valid cache entries (expired entries filtered)")
        else:
            _geocache = OrderedDict()
    except Exception as e:
        logger.warning(f"Failed reading geocache: {e}, starting with empty cache.")
        _geocache = OrderedDict()

def _save_geocache():
    """Save geocache to file, maintaining LRU order"""
    try:
        os.makedirs(os.path.dirname(GEOCACHE_FILE) or '.', exist_ok=True)
        # Convert OrderedDict to regular dict for JSON serialization
        cache_dict = dict(_geocache)
        with open(GEOCACHE_FILE, 'w') as f:
            json.dump(cache_dict, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed saving geocache: {e}")

def _cleanup_cache():
    """Remove expired entries and enforce size limit (LRU eviction)"""
    global _geocache
    current_time = int(time.time())
    ttl_seconds = CACHE_TTL_DAYS * 24 * 60 * 60
    
    # Remove expired entries
    expired_keys = []
    for ip, data in _geocache.items():
        cache_time = data.get('ts', 0)
        if current_time - cache_time >= ttl_seconds:
            expired_keys.append(ip)
    
    for key in expired_keys:
        _geocache.pop(key, None)
    
    # Enforce size limit (LRU: remove oldest entries)
    while len(_geocache) >= MAX_CACHE_SIZE:
        _geocache.popitem(last=False)  # Remove oldest (first) item

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
            line_num = 0
            for line in f:
                line_num += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    attack = json.loads(line)
                    attacks.append(attack)
                except json.JSONDecodeError as e:
                    # Log malformed entries for debugging
                    logger.warning(f"Malformed JSON in {log_file} at line {line_num}: {e}. Line content: {line[:100]}")
                    continue
    except FileNotFoundError:
        return []
    except Exception as e:
        logger.error(f"Error reading attack log {log_file}: {e}")
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

def _check_rate_limit():
    """Check and enforce API rate limiting (45 requests/minute)"""
    global _api_request_times
    current_time = time.time()
    
    with _api_lock:
        # Remove requests older than the rate limit window
        _api_request_times = [t for t in _api_request_times if current_time - t < API_RATE_WINDOW]
        
        # If we're at the limit, calculate delay needed
        if len(_api_request_times) >= API_RATE_LIMIT:
            oldest_request = min(_api_request_times)
            wait_time = API_RATE_WINDOW - (current_time - oldest_request) + 0.1
            if wait_time > 0:
                logger.warning(f"Rate limit reached ({API_RATE_LIMIT} req/min), waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                # Clean up again after wait
                current_time = time.time()
                _api_request_times = [t for t in _api_request_times if current_time - t < API_RATE_WINDOW]
        
        # Record this request
        _api_request_times.append(time.time())

def enrich_with_geo(ip):
    """
    Enrich an IPv4/IPv6 address with lat/lon using ip-api.com with fallback to ipinfo.io.
    Uses local cache to avoid repeated lookups.
    Returns (lat, lon) or (None, None).
    """
    if not ip or ip == 'Unknown':
        return None, None

    # Skip private IP ranges
    if ip.startswith(('127.', '10.', '192.168.', '172.')):
        return None, None

    # Cleanup cache periodically (every 5 minutes)
    global _last_cleanup_time
    current_time = time.time()
    if current_time - _last_cleanup_time > CLEANUP_INTERVAL:
        _cleanup_cache()
        _last_cleanup_time = current_time

    # If already cached, move to end (LRU) and return it
    if ip in _geocache:
        cached = _geocache.pop(ip)  # Remove from current position
        _geocache[ip] = cached  # Add to end (most recently used)
        return cached.get('lat'), cached.get('lon')

    # Enforce rate limiting
    _check_rate_limit()

    # Try primary API (ip-api.com)
    try:
        url = f"{IP_API_URL}/{ip}?fields=status,message,lat,lon,city,country,countryCode,region,regionName,isp,org,as"
        r = requests.get(url, timeout=IP_API_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get('status') == 'success':
            lat = data.get('lat')
            lon = data.get('lon')
            # Store extended geolocation data
            geo_data = {
                'lat': lat,
                'lon': lon,
                'city': data.get('city'),
                'country': data.get('country'),
                'countryCode': data.get('countryCode'),
                'region': data.get('region'),
                'regionName': data.get('regionName'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'as': data.get('as'),
                'ts': int(time.time())
            }
            # Add to cache (LRU: new entries go to end)
            _geocache[ip] = geo_data
            _save_geocache()
            return lat, lon
        else:
            # API returned error, try fallback
            logger.debug(f"ip-api.com failed for {ip}: {data.get('message', 'Unknown error')}")
            raise requests.exceptions.RequestException("Primary API failed")
    except requests.exceptions.RequestException as e:
        # Fallback to ipinfo.io
        logger.info(f"Primary geolocation API failed for {ip}, trying fallback: {e}")
        try:
            fallback_url = f"https://ipinfo.io/{ip}/json"
            r = requests.get(fallback_url, timeout=IP_API_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            
            # Parse ipinfo.io response format
            loc = data.get('loc', '').split(',')
            if len(loc) == 2:
                lat = float(loc[0])
                lon = float(loc[1])
                geo_data = {
                    'lat': lat,
                    'lon': lon,
                    'city': data.get('city', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'countryCode': data.get('country', '')[:2] if data.get('country') else '',
                    'region': data.get('region', 'Unknown'),
                    'regionName': data.get('region', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('org', 'Unknown'),
                    'ts': int(time.time())
                }
                _geocache[ip] = geo_data
                _save_geocache()
                logger.info(f"Fallback geolocation successful for {ip}")
                return lat, lon
        except Exception as fallback_error:
            logger.warning(f"Fallback geolocation also failed for {ip}: {fallback_error}")
        
        # Both APIs failed, cache the failure
        _geocache[ip] = {'lat': None, 'lon': None, 'ts': int(time.time()), 'err': f'Both APIs failed'}
        _save_geocache()
        return None, None
    except Exception as e:
        # Unexpected error: do not crash
        logger.error(f"Unexpected error enriching IP {ip}: {e}")
        _geocache[ip] = {'lat': None, 'lon': None, 'ts': int(time.time()), 'err': f'Error: {str(e)[:50]}'}
        _save_geocache()
        return None, None

def get_geo_details(ip):
    """
    Get extended geolocation details for an IP from cache.
    Returns dict with city, country, ISP, etc. or empty dict.
    """
    if not ip or ip == 'Unknown':
        return {}
    
    cached = _geocache.get(ip, {})
    return {
        'city': cached.get('city', 'Unknown'),
        'country': cached.get('country', 'Unknown'),
        'countryCode': cached.get('countryCode', ''),
        'region': cached.get('regionName', 'Unknown'),
        'isp': cached.get('isp', 'Unknown'),
        'org': cached.get('org', 'Unknown'),
        'as': cached.get('as', 'Unknown')
    }

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
            # Get extended geo details
            geo_details = get_geo_details(ip)

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
                'lon': lon,
                # Extended geolocation
                'city': geo_details.get('city', 'Unknown'),
                'country': geo_details.get('country', 'Unknown'),
                'region': geo_details.get('region', 'Unknown'),
                'isp': geo_details.get('isp', 'Unknown'),
                'org': geo_details.get('org', 'Unknown')
            }
            processed.append(processed_attack)
            # Check and trigger alerts for new attacks
            try:
                check_and_trigger_alerts(processed_attack)
            except Exception as e:
                logger.warning(f"Error checking alerts for attack: {e}")
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
        'countries': {},
        'cities': {},
        'isps': {},
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
        
        # Geographic statistics
        country = a.get('country', 'Unknown')
        if country and country != 'Unknown':
            stats['countries'][country] = stats['countries'].get(country, 0) + 1
        
        city = a.get('city', 'Unknown')
        if city and city != 'Unknown':
            stats['cities'][city] = stats['cities'].get(city, 0) + 1
        
        isp = a.get('isp', 'Unknown')
        if isp and isp != 'Unknown':
            stats['isps'][isp] = stats['isps'].get(isp, 0) + 1

    # Sort geographic data by frequency
    stats['top_countries'] = sorted(stats['countries'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_cities'] = sorted(stats['cities'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_isps'] = sorted(stats['isps'].items(), key=lambda x: x[1], reverse=True)[:10]

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
            # Geographic data
            'countries': {str(k): v for k, v in statistics.get('countries', {}).items()},
            'cities': {str(k): v for k, v in statistics.get('cities', {}).items()},
            'isps': {str(k): v for k, v in statistics.get('isps', {}).items()},
            'top_countries': statistics.get('top_countries', []),
            'top_cities': statistics.get('top_cities', []),
            'top_isps': statistics.get('top_isps', []),
            # include recent_attacks (already sanitized)
            'recent_attacks': statistics['recent_attacks']
        }

        response = Response(render_template(
            'unified_dashboard.html', 
            statistics=sanitized_stats, 
            attacks=processed,
            DASHBOARD_USERNAME=DASHBOARD_USERNAME,
            DASHBOARD_PASSWORD=DASHBOARD_PASSWORD
        ))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        error_msg = f"Error loading dashboard: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        return f"<h1>Internal Server Error</h1><p>{escape(error_msg)}</p><pre>{escape(traceback.format_exc())}</pre>", 500

def check_and_trigger_alerts(attack):
    """Check attack against thresholds and trigger alerts if needed"""
    global _recent_attacks, _attack_counts, _known_countries
    
    current_time = time.time()
    ip = attack.get('ip', 'Unknown')
    attack_type = attack.get('attack_type', '').lower()
    tools = attack.get('tools_detected', '').lower()
    country = attack.get('country', 'Unknown')
    
    # Add to recent attacks
    _recent_attacks.append({
        'attack': attack,
        'timestamp': current_time
    })
    
    # Update attack counts per IP
    if ip not in _attack_counts:
        _attack_counts[ip] = []
    _attack_counts[ip].append(current_time)
    # Clean old entries (older than 1 minute)
    _attack_counts[ip] = [t for t in _attack_counts[ip] if current_time - t < 60]
    
    alerts_triggered = []
    
    # Check for high attack rate
    recent_count = len([a for a in _recent_attacks if current_time - a['timestamp'] < 60])
    if recent_count >= ALERT_THRESHOLDS['high_attack_rate']:
        alert = {
            'type': 'high_attack_rate',
            'severity': 'high',
            'message': f'High attack rate detected: {recent_count} attacks in the last minute',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {'attack_count': recent_count}
        }
        alerts_triggered.append(alert)
    
    # Check for critical attack types
    for critical_type in ALERT_THRESHOLDS['critical_attack_types']:
        if critical_type.lower() in attack_type:
            alert = {
                'type': 'critical_attack',
                'severity': 'critical',
                'message': f'Critical attack detected: {critical_type} from {ip}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': {'attack_type': critical_type, 'ip': ip, 'attack': attack}
            }
            alerts_triggered.append(alert)
            break
    
    # Check for suspicious tools
    for tool in ALERT_THRESHOLDS['suspicious_tools']:
        if tool.lower() in tools:
            alert = {
                'type': 'suspicious_tool',
                'severity': 'high',
                'message': f'Suspicious tool detected: {tool} from {ip}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': {'tool': tool, 'ip': ip, 'attack': attack}
            }
            alerts_triggered.append(alert)
            break
    
    # Check for repeated attacker
    if len(_attack_counts.get(ip, [])) >= ALERT_THRESHOLDS['repeated_attacker']:
        alert = {
            'type': 'repeated_attacker',
            'severity': 'medium',
            'message': f'Repeated attacks from {ip}: {len(_attack_counts[ip])} attacks in last minute',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {'ip': ip, 'count': len(_attack_counts[ip])}
        }
        alerts_triggered.append(alert)
    
    # Check for new country
    if ALERT_THRESHOLDS['new_country'] and country != 'Unknown' and country not in _known_countries:
        _known_countries.add(country)
        alert = {
            'type': 'new_country',
            'severity': 'info',
            'message': f'First attack detected from {country}',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {'country': country, 'ip': ip}
        }
        alerts_triggered.append(alert)
    
    # Process alerts
    for alert in alerts_triggered:
        _process_alert(alert)
    
    return alerts_triggered

def _process_alert(alert):
    """Process alert: log, notify subscribers, trigger responses"""
    # Log alert
    try:
        os.makedirs(os.path.dirname(ALERTS_LOG) or 'logs', exist_ok=True)
        with open(ALERTS_LOG, 'a') as f:
            json.dump(alert, f)
            f.write('\n')
    except Exception as e:
        logger.error(f"Failed to log alert: {e}")
    
    # Add to queue for SSE subscribers
    ALERT_QUEUE.put(alert)
    
    # Trigger automated responses
    if alert['severity'] in ['critical', 'high']:
        _trigger_incident_response(alert)

def _trigger_incident_response(alert):
    """Trigger automated incident response actions"""
    # Webhook notification
    if INCIDENT_RESPONSES.get('webhook_url'):
        try:
            requests.post(
                INCIDENT_RESPONSES['webhook_url'],
                json=alert,
                timeout=5
            )
        except Exception as e:
            logger.warning(f"Webhook notification failed: {e}")
    
    # Email notification (if configured)
    if INCIDENT_RESPONSES.get('notify_email'):
        # Email sending would be implemented here
        logger.info(f"Email notification would be sent to {INCIDENT_RESPONSES['notify_email']}")
    
    # IP blocking (if enabled)
    if INCIDENT_RESPONSES.get('block_ip') and 'ip' in alert.get('data', {}):
        ip = alert['data']['ip']
        logger.warning(f"IP blocking would be triggered for {ip}")

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

@app.route('/api/alerts')
@requires_auth
def api_alerts():
    """Get recent alerts"""
    try:
        alerts = []
        if os.path.exists(ALERTS_LOG):
            with open(ALERTS_LOG, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        # Return most recent 100 alerts
        alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:100]
        return jsonify({'count': len(alerts), 'alerts': alerts})
    except Exception as e:
        logger.error(f"Error loading alerts: {e}")
        return jsonify({'error': 'Failed to load alerts'}), 500

@app.route('/api/alerts/stream')
@requires_auth
def api_alerts_stream():
    """Server-Sent Events stream for real-time alerts"""
    def event_stream():
        while True:
            try:
                # Wait for alert with timeout
                alert = ALERT_QUEUE.get(timeout=30)
                yield f"data: {json.dumps(alert)}\n\n"
            except:
                # Send keepalive
                yield ": keepalive\n\n"
    
    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/attacks/filter', methods=['POST'])
@requires_auth
def api_attacks_filter():
    """Filter attacks by date range, service, attack type, etc."""
    try:
        data = request.get_json() or {}
        raw = load_attack_data()
        processed = process_attack_data(raw)
        
        # Apply filters
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        service = data.get('service')
        attack_type = data.get('attack_type')
        country = data.get('country')
        ip = data.get('ip')
        
        filtered = processed
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            filtered = [a for a in filtered if a.get('timestamp_obj') and datetime.fromisoformat(a['timestamp_obj'].replace('Z', '+00:00')) >= start_dt]
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            filtered = [a for a in filtered if a.get('timestamp_obj') and datetime.fromisoformat(a['timestamp_obj'].replace('Z', '+00:00')) <= end_dt]
        if service:
            filtered = [a for a in filtered if a.get('service', '').lower() == service.lower()]
        if attack_type:
            filtered = [a for a in filtered if a.get('attack_type', '').lower() == attack_type.lower()]
        if country:
            filtered = [a for a in filtered if a.get('country', '').lower() == country.lower()]
        if ip:
            filtered = [a for a in filtered if a.get('ip', '').lower() == ip.lower()]
        
        return jsonify({'count': len(filtered), 'attacks': filtered})
    except Exception as e:
        logger.error(f"Error filtering attacks: {e}")
        return jsonify({'error': 'Failed to filter attacks'}), 500

@app.route('/api/attacks/export', methods=['POST'])
@requires_auth
def api_attacks_export():
    """Export attacks to CSV/JSON"""
    try:
        data = request.get_json() or {}
        format_type = data.get('format', 'json')  # json or csv
        raw = load_attack_data()
        processed = process_attack_data(raw)
        
        # Apply same filters as filter endpoint
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        # ... (same filtering logic)
        
        if format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['timestamp', 'ip', 'country', 'city', 'service', 'attack_type', 'username', 'tools_detected'])
            writer.writeheader()
            for attack in processed:
                writer.writerow({
                    'timestamp': attack.get('timestamp', ''),
                    'ip': attack.get('ip', ''),
                    'country': attack.get('country', ''),
                    'city': attack.get('city', ''),
                    'service': attack.get('service', ''),
                    'attack_type': attack.get('attack_type', ''),
                    'username': attack.get('username', ''),
                    'tools_detected': attack.get('tools_detected', '')
                })
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=attacks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )
        else:
            return jsonify({'count': len(processed), 'attacks': processed})
    except Exception as e:
        logger.error(f"Error exporting attacks: {e}")
        return jsonify({'error': 'Failed to export attacks'}), 500

@app.route('/test-static')
def test_static():
    """Test route to verify static files are accessible"""
    import os
    css_path = os.path.join('static', 'css', 'style.css')
    if os.path.exists(css_path):
        size = os.path.getsize(css_path)
        return jsonify({
            'status': 'OK',
            'message': 'Static files are configured correctly',
            'css_file': css_path,
            'css_size': f"{size / 1024:.2f} KB",
            'css_url': url_for('static', filename='css/style.css'),
            'static_folder': app.static_folder
        })
    else:
        return jsonify({
            'status': 'ERROR',
            'message': 'CSS file not found',
            'css_path': css_path,
            'static_folder': app.static_folder
        }), 404

@app.route('/api/reset', methods=['POST'])
@requires_auth
def api_reset():
    """Reset dashboard: export all data to text file and clear logs"""
    try:
        # Load all current attack data
        raw_attacks = load_attack_data()
        processed = process_attack_data(raw_attacks)
        
        # Create backups directory if it doesn't exist
        backups_dir = os.path.join(os.path.dirname(ATTACKS_LOG) or 'logs', 'backups')
        os.makedirs(backups_dir, exist_ok=True)
        
        # Generate timestamp for backup file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backups_dir, f'attacks_backup_{timestamp}.txt')
        
        # Format data as readable text
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"HONEYPOT ATTACK DATA BACKUP\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Total Attacks: {len(processed)}\n")
            f.write("=" * 80 + "\n\n")
            
            if processed:
                # Write summary statistics
                stats = get_statistics(processed)
                f.write("SUMMARY STATISTICS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total Attacks: {stats['total_attacks']}\n")
                f.write(f"Unique IPs: {stats['unique_ips']}\n")
                f.write(f"\nService Distribution:\n")
                for service, count in sorted(stats['service_distribution'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {service}: {count}\n")
                f.write(f"\nAttack Types:\n")
                for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {attack_type}: {count}\n")
                f.write(f"\nTop Countries:\n")
                for country, count in stats.get('top_countries', [])[:10]:
                    f.write(f"  {country}: {count}\n")
                f.write("\n" + "=" * 80 + "\n\n")
                
                # Write detailed attack logs
                f.write("DETAILED ATTACK LOGS\n")
                f.write("-" * 80 + "\n\n")
                for i, attack in enumerate(processed, 1):
                    f.write(f"Attack #{i}\n")
                    f.write(f"  Timestamp: {attack.get('timestamp', 'N/A')}\n")
                    f.write(f"  IP Address: {attack.get('ip', 'N/A')}\n")
                    f.write(f"  Location: {attack.get('city', 'Unknown')}, {attack.get('country', 'Unknown')}\n")
                    f.write(f"  Service: {attack.get('service', 'N/A')}\n")
                    f.write(f"  Attack Type: {attack.get('attack_type', 'N/A')}\n")
                    f.write(f"  Username: {attack.get('username', 'N/A')}\n")
                    f.write(f"  Tools Detected: {attack.get('tools_detected', 'None')}\n")
                    f.write(f"  ISP: {attack.get('isp', 'Unknown')}\n")
                    f.write(f"  Organization: {attack.get('org', 'Unknown')}\n")
                    if attack.get('lat') and attack.get('lon'):
                        f.write(f"  Coordinates: {attack.get('lat')}, {attack.get('lon')}\n")
                    f.write("\n")
            else:
                f.write("No attack data to backup.\n")
        
        # Clear the attacks log file
        if os.path.exists(ATTACKS_LOG):
            with open(ATTACKS_LOG, 'w') as f:
                f.write('')  # Clear file
        
        # Also clear alerts log (optional)
        if os.path.exists(ALERTS_LOG):
            alerts_backup = os.path.join(backups_dir, f'alerts_backup_{timestamp}.txt')
            try:
                # Backup alerts before clearing
                alerts_data = []
                if os.path.exists(ALERTS_LOG):
                    with open(ALERTS_LOG, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    alerts_data.append(json.loads(line))
                                except:
                                    pass
                
                if alerts_data:
                    with open(alerts_backup, 'w', encoding='utf-8') as f:
                        f.write("=" * 80 + "\n")
                        f.write(f"HONEYPOT ALERTS BACKUP\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                        f.write(f"Total Alerts: {len(alerts_data)}\n")
                        f.write("=" * 80 + "\n\n")
                        for alert in alerts_data:
                            f.write(f"Alert: {alert.get('message', 'N/A')}\n")
                            f.write(f"  Severity: {alert.get('severity', 'N/A')}\n")
                            f.write(f"  Type: {alert.get('type', 'N/A')}\n")
                            f.write(f"  Timestamp: {alert.get('timestamp', 'N/A')}\n")
                            f.write("\n")
                
                # Clear alerts log
                with open(ALERTS_LOG, 'w') as f:
                    f.write('')
            except Exception as e:
                logger.warning(f"Error backing up alerts: {e}")
        
        logger.info(f"Dashboard reset: {len(processed)} attacks backed up to {backup_file}")
        return jsonify({
            'success': True,
            'message': f'Data backed up to {backup_file}',
            'backup_file': backup_file,
            'attacks_backed_up': len(processed)
        })
    except Exception as e:
        logger.error(f"Error resetting dashboard: {e}")
        return jsonify({'error': f'Failed to reset dashboard: {str(e)}'}), 500

@app.route('/api/stats')
@requires_auth
def api_stats():
    """Get statistics with optional date range"""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        raw = load_attack_data()
        processed = process_attack_data(raw)
        
        # Apply date filters if provided
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            processed = [a for a in processed if a.get('timestamp_obj') and datetime.fromisoformat(a['timestamp_obj'].replace('Z', '+00:00')) >= start_dt]
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            processed = [a for a in processed if a.get('timestamp_obj') and datetime.fromisoformat(a['timestamp_obj'].replace('Z', '+00:00')) <= end_dt]
        
        stats = get_statistics(processed)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

def main():
    """Main entry point for dashboard application"""
    try:
        # Ensure directories exist
        os.makedirs(os.path.dirname(ATTACKS_LOG) or 'logs', exist_ok=True)
        os.makedirs(os.path.dirname(GEOCACHE_FILE) or 'logs', exist_ok=True)
        
        print("=" * 60)
        print("  🍯 Honeypot Security Dashboard - Professional Edition")
        print("=" * 60)
        print(f"[*] Starting dashboard on http://0.0.0.0:{FLASK_RUN_PORT}")
        print(f"[*] Local access: http://localhost:{FLASK_RUN_PORT}")
        print(f"[*] Username: {DASHBOARD_USERNAME}")
        print(f"[*] Password: {DASHBOARD_PASSWORD}")
        print(f"[*] Features: Real-time monitoring, Search, Filter, Export")
        print("=" * 60)
        print("[*] Dashboard is ready! Press Ctrl+C to stop.")
        print("=" * 60)
        
        app.run(host='0.0.0.0', port=FLASK_RUN_PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[*] Shutting down dashboard...")
        print("[*] Dashboard stopped successfully.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()
