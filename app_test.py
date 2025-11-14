from flask import Flask, render_template, Response
import json

app = Flask(__name__, template_folder='templates')

@app.route('/')
def dashboard():
    # Dummy example data — replace with your honeypot stats
    statistics = {
        "total_attacks": 2314,
        "unique_ips": 482,
        "top_countries": [["China", 945], ["USA", 321], ["Russia", 120]],
        "service_distribution": {"SSH": 1034, "Telnet": 680, "HTTP": 400},
        "attack_types": {"Bruteforce": 1340, "SQL Injection": 210, "Scan": 764},
        "countries": {"China": 945, "USA": 321, "Russia": 120},
        "recent_attacks": [
            {"timestamp": "2025-11-08 18:22:30", "ip": "45.23.11.5", "city": "Shanghai", "country": "China", "service": "SSH", "attack_type": "Bruteforce", "username": "root", "tools_detected": "Hydra"},
            {"timestamp": "2025-11-08 18:20:14", "ip": "192.168.0.18", "city": "New York", "country": "USA", "service": "HTTP", "attack_type": "SQL Injection", "username": "admin", "tools_detected": "SQLMap"}
        ]
    }

    attacks = [
        {"ip": "45.23.11.5", "lat": 31.23, "lon": 121.47, "city": "Shanghai", "country": "China", "service": "SSH", "attack_type": "Bruteforce"},
        {"ip": "192.168.0.18", "lat": 40.71, "lon": -74.00, "city": "New York", "country": "USA", "service": "HTTP", "attack_type": "SQL Injection"}
    ]

    response = Response(render_template('unified_dashboard.html', statistics=statistics, attacks=attacks))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == "__main__":
    print("=" * 60)
    print("  🧠 Honeypot Dashboard - Test Mode")
    print("=" * 60)
    print("[*] Starting dashboard on http://localhost:5001")
    print("[*] Using dummy data for testing")
    print("[*] Access at: http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5001, debug=True)

