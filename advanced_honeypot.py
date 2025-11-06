import socket
import threading
import logging
import json
from datetime import datetime
import os
import ssl
# Legacy import - fake_library removed, using stub function
def create_fake_service_response(service_type):
    """Stub function for legacy compatibility"""
    responses = {
        'http': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>',
        'https': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>',
        'ftp': '220 Welcome to FTP Server\r\n',
        'mysql': b'\x0a\x35\x2e\x37\x2e\x30\x00',  # MySQL version handshake
        'rdp': b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
    }
    return responses.get(service_type, '')

class AdvancedHoneypot:
    def __init__(self, config=None):
        self.config = config or {
            'services': {
                'http': {'port': 80, 'enabled': True},
                'https': {'port': 443, 'enabled': True},
                'ftp': {'port': 21, 'enabled': True},
                'mysql': {'port': 3306, 'enabled': True},
                'rdp': {'port': 3389, 'enabled': True}
            },
            'log_file': 'logs/advanced_honeypot.log',
            'attack_log': 'logs/attacks.json'
        }
        self.setup_logging()
        self.load_ssl_cert()
        self.active_connections = {}
        self.attack_patterns = self.load_attack_patterns()

    def setup_logging(self):
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            filename=self.config['log_file'],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('advanced_honeypot')

    def load_ssl_cert(self):
        cert_path = 'certs/server.crt'
        key_path = 'certs/server.key'
        if not os.path.exists('certs'):
            os.makedirs('certs')
            self.generate_self_signed_cert()
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(cert_path, key_path)

    def generate_self_signed_cert(self):
        # This is a placeholder - in production, use OpenSSL to generate proper certs
        pass

    def load_attack_patterns(self):
        return {
            'sql_injection': [
                "SELECT", "UNION", "DROP", "--", "';",
                "admin'--", "1=1", "1'='1"
            ],
            'xss': [
                "<script>", "javascript:", "onerror=", "onload=",
                "eval(", "alert("
            ],
            'directory_traversal': [
                "../", "..\\", "/etc/passwd", "c:\\windows\\",
                ".htaccess", "wp-config.php"
            ],
            'command_injection': [
                "|", ";", "`", "$(",
                "&&", "||"
            ]
        }

    def detect_attack_type(self, data):
        detected_attacks = []
        data_str = str(data).lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if pattern.lower() in data_str:
                    detected_attacks.append(attack_type)
                    break
        
        return list(set(detected_attacks))

    def log_attack(self, client_address, service, data, attack_types):
        attack_info = {
            'timestamp': datetime.now().isoformat(),
            'ip_address': client_address[0],
            'port': client_address[1],
            'service': service,
            'data': str(data),
            'attack_types': attack_types,
            'tools_detected': self.detect_tools(data)
        }
        
        with open(self.config['attack_log'], 'a') as f:
            json.dump(attack_info, f)
            f.write('\n')
        
        self.logger.warning(f"Attack detected from {client_address[0]}: {attack_types}")

    def detect_tools(self, data):
        # Dictionary of common penetration testing tools and their signatures
        tool_signatures = {
            'nmap': ['nmap', 'NSE/', 'Nmap Scripting Engine'],
            'metasploit': ['Metasploit', 'msf', 'meterpreter'],
            'sqlmap': ['sqlmap', 'SQL injection', 'parameter is vulnerable'],
            'hydra': ['hydra', 'login combination', 'password tries'],
            'nikto': ['nikto', 'CGI Scanning'],
            'dirb': ['dirb', 'directory scan'],
            'burpsuite': ['burp', 'burpsuite', 'X-Burp']
        }
        
        detected_tools = []
        data_str = str(data).lower()
        
        for tool, signatures in tool_signatures.items():
            for sig in signatures:
                if sig.lower() in data_str:
                    detected_tools.append(tool)
                    break
        
        return list(set(detected_tools))

    def handle_connection(self, client_socket, client_address, service):
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                # Detect attack patterns
                attack_types = self.detect_attack_type(data)
                if attack_types:
                    self.log_attack(client_address, service, data, attack_types)

                # Generate fake response based on the service
                response = create_fake_service_response(service)
                if isinstance(response, bytes):
                    client_socket.send(response)
                else:
                    client_socket.send(response.encode())

        except Exception as e:
            self.logger.error(f"Error handling {service} connection from {client_address}: {str(e)}")
        finally:
            client_socket.close()
            if client_address in self.active_connections:
                del self.active_connections[client_address]

    def start_service(self, service, port):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            self.logger.info(f"Started {service} honeypot on port {port}")
            
            while True:
                client_socket, client_address = server_socket.accept()
                
                if service == 'https':
                    client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                
                self.active_connections[client_address] = {
                    'service': service,
                    'start_time': datetime.now()
                }
                
                thread = threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, client_address, service)
                )
                thread.daemon = True
                thread.start()

        except Exception as e:
            self.logger.error(f"Error starting {service} service: {str(e)}")

    def start(self):
        for service, config in self.config['services'].items():
            if config['enabled']:
                thread = threading.Thread(
                    target=self.start_service,
                    args=(service, config['port'])
                )
                thread.daemon = True
                thread.start()

        try:
            while True:
                # Keep the main thread alive
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down honeypot services...")
