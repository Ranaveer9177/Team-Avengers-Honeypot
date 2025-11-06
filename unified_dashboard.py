import json
from flask import Flask, render_template, request, Response
from datetime import datetime
import os
from functools import wraps
from markupsafe import escape

app = Flask(__name__)

# Security: Load dashboard credentials from environment or use defaults
DASHBOARD_USERNAME = os.environ.get('DASHBOARD_USERNAME', 'admin')
DASHBOARD_PASSWORD = os.environ.get('DASHBOARD_PASSWORD', 'honeypot@91771')

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
    # Content Security Policy - restrict sources for scripts, styles, etc.
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Prevent referrer leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Remove server header (security through obscurity)
    response.headers.pop('Server', None)
    return response

def load_attack_data():
    attacks = []
    log_file = 'logs/attacks.json'
    
    if not os.path.exists(log_file):
        return []
        
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    attack = json.loads(line)
                    attacks.append(attack)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
        
    return attacks

def sanitize_string(value, max_length=100):
    """Sanitize string values to prevent XSS attacks"""
    if not isinstance(value, str):
        value = str(value)
    # Truncate long strings
    if len(value) > max_length:
        value = value[:max_length] + '...'
    # Escape HTML special characters (Jinja2 auto-escapes, but this adds extra safety)
    return escape(value)

def process_attack_data(attacks):
    """Process and sanitize attack data for safe display"""
    processed = []
    
    for attack in attacks:
        # Sanitize all string fields to prevent XSS
        processed_attack = {
            'timestamp': datetime.fromisoformat(attack['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'ip': sanitize_string(attack.get('ip', 'Unknown'), max_length=45),  # IPv6 max length
            'device_name': sanitize_string(attack.get('device_name', 'Unknown Device'), max_length=50),
            'service': sanitize_string(attack.get('service', 'unknown'), max_length=20),
            'attack_type': sanitize_string(attack.get('attack_type', 'unknown'), max_length=30),
            'tools_detected': sanitize_string(
                ', '.join(attack.get('tools_detected', [])) or 'None detected',
                max_length=100
            ),
            'username': sanitize_string(attack.get('username', 'N/A'), max_length=50),
            'auth_method': sanitize_string(
                'Key' if attack.get('key_attempted') else 'Password' if attack.get('password') else 'N/A',
                max_length=20
            )
        }
        processed.append(processed_attack)
    
    return processed

def get_statistics(attacks):
    stats = {
        'total_attacks': len(attacks),
        'unique_ips': len(set(attack['ip'] for attack in attacks)),
        'service_distribution': {},
        'attack_types': {},
        'tools_detected': {},
        'recent_attacks': []
    }
    
    for attack in attacks:
        # Service distribution
        service = attack.get('service', 'unknown')
        stats['service_distribution'][service] = stats['service_distribution'].get(service, 0) + 1
        
        # Attack types
        attack_type = attack.get('attack_type', 'unknown')
        stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
        
        # Tools detected
        for tool in attack.get('tools_detected', []):
            stats['tools_detected'][tool] = stats['tools_detected'].get(tool, 0) + 1
    
    # Get most recent attacks
    stats['recent_attacks'] = sorted(
        attacks,
        key=lambda x: datetime.fromisoformat(x['timestamp']),
        reverse=True
    )[:10]
    
    return stats

@app.route('/')
@requires_auth
def dashboard():
    """Main dashboard route - requires authentication"""
    attacks = load_attack_data()
    processed_attacks = process_attack_data(attacks)
    statistics = get_statistics(attacks)
    
    # Sanitize statistics data before passing to template
    sanitized_stats = {
        'total_attacks': statistics['total_attacks'],
        'unique_ips': statistics['unique_ips'],
        'service_distribution': {
            sanitize_string(k): v 
            for k, v in statistics['service_distribution'].items()
        },
        'attack_types': {
            sanitize_string(k): v 
            for k, v in statistics['attack_types'].items()
        },
        'tools_detected': {
            sanitize_string(k): v 
            for k, v in statistics['tools_detected'].items()
        },
        'recent_attacks': statistics['recent_attacks']
    }
    
    return render_template(
        'unified_dashboard.html',
        attacks=processed_attacks,
        statistics=sanitized_stats
    )

if __name__ == '__main__':
    # Get port from environment variable or use 5001 as default
    port = int(os.environ.get('FLASK_RUN_PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)