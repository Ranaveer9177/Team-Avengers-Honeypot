import json
from flask import Flask, render_template
from datetime import datetime

app = Flask(__name__)

def load_attack_data():
    attacks = []
    try:
        with open('logs/attack_details.json', 'r') as f:
            for line in f:
                attacks.append(json.loads(line))
    except FileNotFoundError:
        return []
    return attacks

@app.route('/')
def dashboard():
    attacks = load_attack_data()
    
    # Process attack data for display
    processed_attacks = []
    for attack in attacks:
        processed_attack = {
            'ip': attack['ip'],
            'timestamp': datetime.fromisoformat(attack['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'username': attack['username'],
            'auth_method': 'Key' if attack['key_attempted'] else 'Password',
            'client_version': attack['client_version']
        }
        processed_attacks.append(processed_attack)
    
    return render_template('ssh_dashboard.html', attacks=processed_attacks)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)