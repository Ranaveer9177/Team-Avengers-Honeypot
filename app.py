#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import datetime
from pathlib import Path
from collections import defaultdict, Counter
import threading
import time

# Optional GeoIP
try:
    import geoip2.database
except Exception:
    geoip2 = None

APP_TITLE = 'HoneyPot Hero'
LOG_DIR = Path("honeypot_logs")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key-2025'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active connections for broadcasting
active_connections = set()


class GeoIPTracker:
    def __init__(self, db_path='GeoLite2-City.mmdb'):
        self.reader = None
        if geoip2 is None:
            return
        try:
            self.reader = geoip2.database.Reader(db_path)
        except Exception:
            print("GeoIP database not found. Download GeoLite2-City.mmdb from MaxMind and place it alongside app.py.")
            self.reader = None

    def get_location(self, ip_address):
        if not self.reader:
            return None
        try:
            response = self.reader.city(ip_address)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except Exception:
            return None

    def close(self):
        if self.reader:
            self.reader.close()


class AttackerLeaderboard:
    """Manage attacker statistics and rankings"""

    def __init__(self, geoip_tracker=None):
        self.geoip_tracker = geoip_tracker
        self.attackers = defaultdict(lambda: {
            'ip': '',
            'total_attempts': 0,
            'unique_usernames': set(),
            'unique_passwords': set(),
            'commands_executed': [],
            'first_seen': None,
            'last_seen': None,
            'threat_score': 0,
            'geo': None,
        })
        self._lock = threading.Lock()
        self.load_data()

    def load_data(self):
        """Load attack data from JSON logs"""
        if not LOG_DIR.exists():
            return
        # Load login attempts
        for log_file in sorted(LOG_DIR.glob("attacks_*.json")):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        self.process_attack(data)
                    except Exception:
                        continue
        # Load commands
        for log_file in sorted(LOG_DIR.glob("commands_*.json")):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        self.process_command(data)
                    except Exception:
                        continue
        self.calculate_threat_scores()

    def process_attack(self, data):
        """Process a login attempt"""
        ip = data['ip']
        timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        with self._lock:
            attacker = self.attackers[ip]
            attacker['ip'] = ip
            attacker['total_attempts'] += 1
            attacker['unique_usernames'].add(data.get('username'))
            if data.get('auth_type') == 'password':
                attacker['unique_passwords'].add(data.get('credential'))
            if attacker['first_seen'] is None:
                attacker['first_seen'] = timestamp
            attacker['last_seen'] = timestamp
            if attacker['geo'] is None and self.geoip_tracker is not None:
                attacker['geo'] = self.geoip_tracker.get_location(ip)

    def process_command(self, data):
        """Process a command execution"""
        ip = data['ip']
        with self._lock:
            self.attackers[ip]['commands_executed'].append({
                'timestamp': data['timestamp'],
                'command': data['command']
            })

    def calculate_threat_scores(self):
        """Calculate threat score based on activity"""
        with self._lock:
            for ip, data in self.attackers.items():
                score = 0
                score += data['total_attempts'] * 1
                score += len(data['unique_usernames']) * 5
                score += len(data['unique_passwords']) * 3
                score += len(data['commands_executed']) * 10
                if data['first_seen'] and data['last_seen']:
                    duration = (data['last_seen'] - data['first_seen']).seconds
                    score += min(duration // 60, 50)
                data['threat_score'] = score

    def get_leaderboard(self, limit=10):
        """Get top attackers by threat score"""
        with self._lock:
            sorted_attackers = sorted(
                self.attackers.items(),
                key=lambda x: x[1]['threat_score'],
                reverse=True
            )[:limit]
            leaderboard = []
            for rank, (ip, data) in enumerate(sorted_attackers, 1):
                leaderboard.append({
                    'rank': rank,
                    'ip': ip,
                    'total_attempts': data['total_attempts'],
                    'unique_usernames': len(data['unique_usernames']),
                    'unique_passwords': len(data['unique_passwords']),
                    'commands_count': len(data['commands_executed']),
                    'threat_score': data['threat_score'],
                    'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
                    'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None,
                    'geo': data['geo'],
                })
            return leaderboard

    def get_statistics(self):
        """Get overall statistics"""
        with self._lock:
            total_attackers = len(self.attackers)
            total_attempts = sum(a['total_attempts'] for a in self.attackers.values())
            total_commands = sum(len(a['commands_executed']) for a in self.attackers.values())
            all_usernames = []
            for data in self.attackers.values():
                all_usernames.extend([u for u in data['unique_usernames'] if u is not None])
            common_usernames = Counter(all_usernames).most_common(10)
            return {
                'total_attackers': total_attackers,
                'total_attempts': total_attempts,
                'total_commands': total_commands,
                'common_usernames': [{'username': u, 'count': c} for u, c in common_usernames],
                'active_now': len(active_connections),
            }


geoip_tracker = GeoIPTracker()
leaderboard = AttackerLeaderboard(geoip_tracker=geoip_tracker)


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/leaderboard')
def api_leaderboard():
    return jsonify(leaderboard.get_leaderboard())


@app.route('/api/statistics')
def api_statistics():
    return jsonify(leaderboard.get_statistics())


@app.route('/api/event', methods=['POST'])
def api_event():
    """Receive events pushed from the honeypot and broadcast them."""
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'invalid json'}), 400

    if not isinstance(payload, dict) or 'event_type' not in payload:
        return jsonify({'error': 'missing event_type'}), 400

    # Update leaderboard and broadcast
    etype = payload['event_type']
    if etype == 'login_attempt':
        leaderboard.process_attack(payload)
    elif etype == 'command_execution':
        leaderboard.process_command(payload)
    leaderboard.calculate_threat_scores()

    socketio.emit('new_attack', {
        'type': etype,
        'data': payload,
        'leaderboard': leaderboard.get_leaderboard(5)
    }, broadcast=True)

    return jsonify({'ok': True})


@socketio.on('connect')
def handle_connect():
    active_connections.add(request.sid)
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': f'Connected to {APP_TITLE}'})


@socketio.on('disconnect')
def handle_disconnect():
    active_connections.discard(request.sid)
    print(f'Client disconnected: {request.sid}')


def broadcast_new_attack(attack_data):
    socketio.emit('new_attack', attack_data, broadcast=True)


def monitor_logs():
    """Monitor log files for new attacks and commands and broadcast updates"""
    last_position = {}
    while True:
        time.sleep(2)
        # attacks
        for log_file in LOG_DIR.glob("attacks_*.json"):
            file_path = str(log_file)
            if file_path not in last_position:
                last_position[file_path] = 0
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    f.seek(last_position[file_path])
                    for line in f:
                        try:
                            attack = json.loads(line)
                            leaderboard.process_attack(attack)
                            leaderboard.calculate_threat_scores()
                            broadcast_new_attack({
                                'type': 'login_attempt',
                                'data': attack,
                                'leaderboard': leaderboard.get_leaderboard(5)
                            })
                        except Exception:
                            continue
                    last_position[file_path] = f.tell()
            except FileNotFoundError:
                continue
        # commands
        for log_file in LOG_DIR.glob("commands_*.json"):
            file_path = str(log_file)
            if file_path not in last_position:
                last_position[file_path] = 0
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    f.seek(last_position[file_path])
                    for line in f:
                        try:
                            cmd = json.loads(line)
                            leaderboard.process_command(cmd)
                            leaderboard.calculate_threat_scores()
                            broadcast_new_attack({
                                'type': 'command_execution',
                                'data': cmd,
                                'leaderboard': leaderboard.get_leaderboard(5)
                            })
                        except Exception:
                            continue
                    last_position[file_path] = f.tell()
            except FileNotFoundError:
                continue


monitor_thread = threading.Thread(target=monitor_logs, daemon=True)
monitor_thread.start()


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
