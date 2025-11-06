import socket
import threading
import json
import logging
from datetime import datetime
import os
from advanced_honeypot import AdvancedHoneypot

class HoneypotServer:
    def __init__(self, config_file='config/honeypot_config.json'):
        self.honeypots = {}
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.setup_monitoring()

    def load_config(self, config_file):
        default_config = {
            'control_port': 8080,
            'honeypots': {
                'default': {
                    'services': {
                        'http': {'port': 80, 'enabled': True},
                        'https': {'port': 443, 'enabled': True},
                        'ftp': {'port': 21, 'enabled': True},
                        'mysql': {'port': 3306, 'enabled': True},
                        'rdp': {'port': 3389, 'enabled': True}
                    }
                }
            },
            'log_directory': 'logs',
            'monitoring_interval': 60  # seconds
        }

        os.makedirs('config', exist_ok=True)
        
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create default config if it doesn't exist
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    def setup_logging(self):
        os.makedirs(self.config['log_directory'], exist_ok=True)
        logging.basicConfig(
            filename=f"{self.config['log_directory']}/honeypot_server.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('honeypot_server')

    def setup_monitoring(self):
        self.monitoring_thread = threading.Thread(target=self.monitor_honeypots)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

    def monitor_honeypots(self):
        while True:
            try:
                self.collect_statistics()
                import time
                time.sleep(self.config['monitoring_interval'])
            except Exception as e:
                self.logger.error(f"Error in monitoring: {str(e)}")

    def collect_statistics(self):
        stats = {
            'timestamp': datetime.now().isoformat(),
            'honeypots': {}
        }

        for name, honeypot in self.honeypots.items():
            stats['honeypots'][name] = {
                'active_connections': len(honeypot.active_connections),
                'services': {
                    service: {'enabled': config['enabled'], 'port': config['port']}
                    for service, config in honeypot.config['services'].items()
                }
            }

        # Save statistics
        stats_file = f"{self.config['log_directory']}/statistics.json"
        with open(stats_file, 'a') as f:
            json.dump(stats, f)
            f.write('\n')

    def start_honeypot(self, name, config):
        if name in self.honeypots:
            self.logger.warning(f"Honeypot {name} already running")
            return False

        try:
            honeypot = AdvancedHoneypot(config)
            self.honeypots[name] = honeypot
            honeypot.start()
            self.logger.info(f"Started honeypot: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Error starting honeypot {name}: {str(e)}")
            return False

    def stop_honeypot(self, name):
        if name not in self.honeypots:
            self.logger.warning(f"Honeypot {name} not found")
            return False

        try:
            # Implement graceful shutdown
            del self.honeypots[name]
            self.logger.info(f"Stopped honeypot: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping honeypot {name}: {str(e)}")
            return False

    def handle_control_connection(self, client_socket, address):
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                command = json.loads(data.decode())
                response = self.handle_command(command)
                client_socket.send(json.dumps(response).encode())

        except Exception as e:
            self.logger.error(f"Error handling control connection from {address}: {str(e)}")
        finally:
            client_socket.close()

    def handle_command(self, command):
        try:
            if command['action'] == 'start':
                success = self.start_honeypot(command['name'], command.get('config'))
                return {'status': 'success' if success else 'error'}
            
            elif command['action'] == 'stop':
                success = self.stop_honeypot(command['name'])
                return {'status': 'success' if success else 'error'}
            
            elif command['action'] == 'status':
                return {
                    'status': 'success',
                    'honeypots': {
                        name: {'active': True} for name in self.honeypots
                    }
                }
            
            else:
                return {'status': 'error', 'message': 'Unknown command'}

        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def start(self):
        # Start control server
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control_socket.bind(('0.0.0.0', self.config['control_port']))
        control_socket.listen(5)

        self.logger.info(f"Honeypot server listening on port {self.config['control_port']}")

        # Start default honeypots
        for name, config in self.config['honeypots'].items():
            self.start_honeypot(name, config)

        try:
            while True:
                client_socket, address = control_socket.accept()
                thread = threading.Thread(
                    target=self.handle_control_connection,
                    args=(client_socket, address)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            self.logger.info("Shutting down honeypot server...")
            for name in list(self.honeypots.keys()):
                self.stop_honeypot(name)

if __name__ == '__main__':
    server = HoneypotServer()
    server.start()
