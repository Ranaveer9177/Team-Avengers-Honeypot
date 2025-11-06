import json
from flask import Flask, render_template
from datetime import datetime
import os

app = Flask(__name__)

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

def process_attack_data(attacks):
    processed = []
    
    for attack in attacks:
        processed_attack = {
            'timestamp': datetime.fromisoformat(attack['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'ip': attack['ip'],
            'device_name': attack.get('device_name', 'Unknown Device'),
            'service': attack.get('service', 'unknown'),
            'attack_type': attack.get('attack_type', 'unknown'),
            'tools_detected': ', '.join(attack.get('tools_detected', [])) or 'None detected',
            'username': attack.get('username', 'N/A'),
            'auth_method': 'Key' if attack.get('key_attempted') else 'Password' if attack.get('password') else 'N/A'
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
def dashboard():
    attacks = load_attack_data()
    processed_attacks = process_attack_data(attacks)
    statistics = get_statistics(attacks)
    
    return render_template(
        'unified_dashboard.html',
        attacks=processed_attacks,
        statistics=statistics
    )

if __name__ == '__main__':
    # Get port from environment variable or use 5001 as default
    port = int(os.environ.get('FLASK_RUN_PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)