import socket
import threading
import paramiko
import logging
import json
import ssl
from datetime import datetime
import os
import secrets
import string
from socket import gethostbyaddr, herror

class UnifiedHoneypot(paramiko.ServerInterface):
    def __init__(self, allowed_key=None):
        self.event = threading.Event()
        self.allowed_key = allowed_key
        
        self.attack_details = {
            'ip': None,
            'device_name': None,
            'timestamp': None,
            'username': None,
            'password': None,
            'key_attempted': None,
            'client_version': None,
            'attack_type': None,
            'tools_detected': [],
            'service': 'ssh'
        }
        self.attack_patterns = self.load_attack_patterns()

    def check_auth_password(self, username, password):
        self.attack_details['username'] = username
        self.attack_details['password'] = password
        self.attack_details['attack_type'] = 'password_auth'
        
        # Log the attempt
        print(f"Login attempt - Username: {username}, Password: {password}, Expected: {self.current_password}")
        
        # Check against the generated password
        if username == "admin" and password == self.current_password:
            self.event.set()  # Signal successful authentication
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.attack_details['username'] = username
        self.attack_details['key_attempted'] = key.get_base64()
        self.attack_details['attack_type'] = 'key_auth'
        
        if self.allowed_key and key.get_base64() == self.allowed_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return 'password'  # Only allow password authentication

    def load_attack_patterns(self):
        return {
            'sql_injection': [
                "SELECT", "UNION", "DROP", "--", "';",
                "admin'--", "1=1", "1'='1"
            ],
            'command_injection': [
                "|", ";", "`", "$(",
                "&&", "||"
            ],
            'reconnaissance': [
                "uname -a", "cat /etc/passwd", "id",
                "whoami", "netstat", "ps aux"
            ]
        }

class UnifiedHoneypotServer:
    def __init__(self, config_file='config/unified_honeypot.json'):
        self.load_config(config_file)
        self.setup_logging()
        self.load_host_key()
        self.setup_ssl()
        self.active_connections = {}
        self.tool_signatures = self.load_tool_signatures()
        
        # Generate password in format Honeypot@XXXXX where X are random numbers
        random_numbers = ''.join(secrets.choice(string.digits) for _ in range(5))
        self.ssh_password = f"Honeypot@{random_numbers}"
        print("\n" + "="*50)
        print(f"[!] IMPORTANT: New SSH Password Generated")
        print(f"[!] Username: admin")
        print(f"[!] Password: {self.ssh_password}")
        print("="*50 + "\n")
        print(f"\n[*] Generated new SSH password: {self.ssh_password}\n")

    def load_config(self, config_file):
        default_config = {
            'ssh_port': 2222,
            'http_port': 8080,
            'https_port': 8443,
            'ftp_port': 2121,
            'mysql_port': 3306,
            'log_dir': 'logs',
            'ssh_key_dir': 'ssh_keys',
            'cert_dir': 'certs'
        }
        
        os.makedirs('config', exist_ok=True)
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = default_config
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)

    def setup_logging(self):
        os.makedirs(self.config['log_dir'], exist_ok=True)
        logging.basicConfig(
            filename=f"{self.config['log_dir']}/unified_honeypot.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('unified_honeypot')

    def load_host_key(self):
        key_path = f"{self.config['ssh_key_dir']}/server.key"
        
        # The key should already exist and have proper permissions from the start script
        try:
            self.host_key = paramiko.RSAKey(filename=key_path)
        except Exception as e:
            self.logger.error(f"Error loading SSH host key: {str(e)}")
            raise

    def setup_ssl(self):
        os.makedirs(self.config['cert_dir'], exist_ok=True)
        cert_path = f"{self.config['cert_dir']}/server.crt"
        key_path = f"{self.config['cert_dir']}/server.key"
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            self.generate_self_signed_cert()
        
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(cert_path, key_path)

    def generate_self_signed_cert(self):
        # Implementation for generating self-signed cert (using OpenSSL)
        pass

    def load_tool_signatures(self):
        return {
            'nmap': ['nmap', 'NSE/', 'Nmap Scripting Engine'],
            'metasploit': ['Metasploit', 'msf', 'meterpreter'],
            'hydra': ['hydra', 'login combination'],
            'medusa': ['medusa', 'parallel login brute-forcer'],
            'burpsuite': ['burp', 'burpsuite', 'X-Burp'],
            'sqlmap': ['sqlmap', 'SQL injection'],
            'nikto': ['nikto', 'CGI Scanning']
        }

    def get_device_name(self, ip):
        try:
            hostname, _, _ = gethostbyaddr(ip)
            return hostname
        except (herror, socket.error):
            return "Unknown Device"

    def detect_tools(self, data):
        detected = []
        data_str = str(data).lower()
        
        for tool, signatures in self.tool_signatures.items():
            if any(sig.lower() in data_str for sig in signatures):
                detected.append(tool)
        
        return list(set(detected))

    def log_attack(self, attack_details):
        attack_log_path = f"{self.config['log_dir']}/attacks.json"
        
        with open(attack_log_path, 'a') as f:
            json.dump(attack_details, f)
            f.write('\n')
        
        self.logger.warning(
            f"Attack detected - IP: {attack_details['ip']}, "
            f"Service: {attack_details['service']}, "
            f"Type: {attack_details['attack_type']}"
        )

    def handle_ssh_connection(self, client, addr):
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            
            honeypot = UnifiedHoneypot(self.config.get('allowed_key'))
            honeypot.current_password = self.ssh_password
            honeypot.attack_details['ip'] = addr[0]
            honeypot.attack_details['device_name'] = self.get_device_name(addr[0])
            honeypot.attack_details['timestamp'] = datetime.now().isoformat()
            
            transport.start_server(server=honeypot)
            
            # Wait for authentication
            channel = transport.accept(20)
            if channel is None:
                print("No channel")
                transport.close()
                return

            # Wait for authentication to complete
            honeypot.event.wait(10)
            if not honeypot.event.is_set():
                print("Auth timeout")
                transport.close()
                return

            # Log successful login
            print(f"\n[+] Successful SSH login from {addr[0]}\n")
            
            # Setup terminal
            channel.send('Welcome to Ubuntu 20.04.3 LTS\n\n')
            
            # Interactive shell loop
            while True:
                channel.send('$ ')
                command = ''
                try:
                    while True:
                        char = channel.recv(1)
                        if not char:
                            break
                        if char == b'\r':
                            channel.send(b'\n')
                            break
                        elif char == b'\x03':  # Ctrl+C
                            channel.send(b'^C\n')
                            break
                        else:
                            command += char.decode('utf-8', errors='ignore')
                            channel.send(char)
                except Exception as e:
                    print(f"Error reading command: {str(e)}")
                    break
                    
                    if not char:  # Connection closed
                        break
                        
                    command = command.strip()
                    if command == 'exit':
                        break

                    # Log commands for analysis
                    print(f"[*] Command executed: {command}")
                    
                    # Simulate command output
                    if command == 'whoami':
                        channel.send('admin\n')
                    elif command == 'pwd':
                        channel.send('/home/admin\n')
                    elif command == 'ls':
                        channel.send('Documents\nDownloads\nDesktop\n')
                    else:
                        channel.send(f"bash: {command}: command not found\n")

                if command.strip() == 'exit':
                    break

                # Detect tools from command
                tools = self.detect_tools(command)
                if tools:
                    honeypot.attack_details['tools_detected'].extend(tools)
                    self.log_attack(honeypot.attack_details)

                channel.send(f"bash: {command.strip()}: command not found\n")

        except Exception as e:
            self.logger.error(f"SSH Error from {addr[0]}: {str(e)}")
        finally:
            try:
                transport.close()
            except:
                pass

    def handle_web_connection(self, client_socket, addr, is_https=False):
        try:
            if is_https:
                client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)

            data = client_socket.recv(4096)
            if data:
                request = data.decode('utf-8', errors='ignore')
                lines = request.split('\r\n')
                method = lines[0].split()[0] if lines and lines[0] else 'UNKNOWN'
                path = lines[0].split()[1] if lines and len(lines[0].split()) > 1 else '/'

                # Parse POST data if present
                post_data = {}
                if method == 'POST' and '/login' in path:
                    body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''
                    post_data = {}
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            post_data[key] = value
                    
                    # Log login attempts
                    if 'username' in post_data and 'password' in post_data:
                        attack_details = {
                            'ip': addr[0],
                            'device_name': self.get_device_name(addr[0]),
                            'timestamp': datetime.now().isoformat(),
                            'service': 'https' if is_https else 'http',
                            'username': post_data['username'],
                            'password': post_data['password'],
                            'tools_detected': self.detect_tools(data),
                            'attack_type': 'brute_force_web'
                        }
                        self.log_attack(attack_details)
                        
                        # Get template and insert error message
                        with open('src/templates/login.html', 'r') as f:
                            template = f.read()
                        
                        # Different error messages to make it look more realistic
                        error_messages = [
                            "Invalid username or password",
                            "Login failed. Please check your credentials",
                            "Incorrect login details",
                            "Authentication failed",
                            "Access denied. Please try again"
                        ]
                        error_msg = secrets.choice(error_messages)
                        
                        # Replace template variables
                        response_body = template.replace('{% if error %}{% endif %}', 
                            f'<div class="error">{error_msg}</div>')
                        
                else:
                    # For GET requests or non-login paths, show the login form
                    with open('src/templates/login.html', 'r') as f:
                        response_body = f.read().replace('{% if error %}', '').replace('{% endif %}', '')
                        if method != 'POST':
                            attack_details = {
                                'ip': addr[0],
                                'device_name': self.get_device_name(addr[0]),
                                'timestamp': datetime.now().isoformat(),
                                'service': 'https' if is_https else 'http',
                                'data': request,
                                'tools_detected': self.detect_tools(data),
                                'attack_type': 'web_request'
                            }
                            self.log_attack(attack_details)

                response = "HTTP/1.1 200 OK\r\n"
                response += "Server: Apache/2.4.41 (Ubuntu)\r\n"
                response += "Content-Type: text/html\r\n"
                response += f"Content-Length: {len(response_body)}\r\n"
                response += "\r\n"
                response += response_body

                client_socket.send(response.encode())

        except Exception as e:
            self.logger.error(f"Web Error from {addr[0]}: {str(e)}")
        finally:
            client_socket.close()

    def start_service(self, service_type):
        port = self.config[f'{service_type}_port']
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        self.logger.info(f"Started {service_type} honeypot listening on 0.0.0.0:{port}")
        
        while True:
            client, addr = server_socket.accept()
            self.logger.info(f"Connection from {addr[0]}:{addr[1]} on {service_type}")
            
            if service_type == 'ssh':
                thread = threading.Thread(
                    target=self.handle_ssh_connection,
                    args=(client, addr)
                )
            else:
                thread = threading.Thread(
                    target=self.handle_web_connection,
                    args=(client, addr, service_type == 'https')
                )
            
            thread.daemon = True
            thread.start()

    def start(self):
        services = ['ssh', 'http', 'https', 'ftp', 'mysql']
        
        for service in services:
            thread = threading.Thread(target=self.start_service, args=(service,))
            thread.daemon = True
            thread.start()

        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down unified honeypot...")

if __name__ == '__main__':
    server = UnifiedHoneypotServer()
    server.start()