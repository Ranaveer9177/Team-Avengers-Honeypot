import socket
import sys
import threading
import paramiko
import logging
import json
from datetime import datetime
import os

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, allowed_key):
        self.event = threading.Event()
        self.allowed_key = allowed_key
        self.attack_details = {
            'ip': None,
            'timestamp': None,
            'username': None,
            'password': None,
            'key_attempted': None,
            'client_version': None
        }

    def check_auth_password(self, username, password):
        self.attack_details['username'] = username
        self.attack_details['password'] = password
        # Always reject password authentication
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.attack_details['username'] = username
        self.attack_details['key_attempted'] = key.get_base64()
        
        if key.get_base64() == self.allowed_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'publickey,password'

class SSHServer:
    def __init__(self, host='0.0.0.0', port=2222, real_port=22):
        self.host = host
        self.port = port
        self.real_port = real_port
        self.setup_logging()
        self.load_host_key()
        
        # Load or generate allowed key
        self.allowed_key = self.load_allowed_key()

    def setup_logging(self):
        logging.basicConfig(
            filename='logs/ssh_honeypot.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ssh_honeypot')

    def load_host_key(self):
        if not os.path.exists('ssh_keys'):
            os.makedirs('ssh_keys')
        
        host_key_path = 'ssh_keys/server.key'
        if not os.path.exists(host_key_path):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(host_key_path)
        self.host_key = paramiko.RSAKey(filename=host_key_path)

    def load_allowed_key(self):
        key_path = 'ssh_keys/allowed_key.pub'
        if os.path.exists(key_path):
            with open(key_path, 'r') as f:
                return f.read().strip()
        return None

    def save_attack_details(self, details):
        with open('logs/attack_details.json', 'a') as f:
            json.dump(details, f)
            f.write('\n')

    def handle_connection(self, client, addr):
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            
            honeypot = SSHHoneypot(self.allowed_key)
            honeypot.attack_details['ip'] = addr[0]
            honeypot.attack_details['timestamp'] = datetime.now().isoformat()
            
            # Safe version decoding with error handling
            try:
                if transport.remote_version is not None:
                    honeypot.attack_details['client_version'] = transport.remote_version.decode('utf-8', errors='replace')
                else:
                    honeypot.attack_details['client_version'] = 'Unknown'
            except (AttributeError, UnicodeDecodeError) as e:
                self.logger.warning(f"Error decoding remote version from {addr[0]}: {e}")
                honeypot.attack_details['client_version'] = 'Unknown'

            transport.start_server(server=honeypot)

            channel = transport.accept(20)
            if channel is None:
                transport.close()
                return

            # If we reach here, authentication failed and we're in the honeypot
            channel.send('Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)\n')
            
            # Log the attack details
            self.save_attack_details(honeypot.attack_details)
            self.logger.info(f"Attack attempt from {addr[0]}: {honeypot.attack_details}")

            # Simulate a basic shell
            while True:
                channel.send('$ ')
                command = ''
                while True:
                    char = channel.recv(1)
                    if char == b'\r':
                        channel.send(b'\n')
                        break
                    elif char == b'\x03':  # Ctrl+C
                        channel.send(b'^C\n')
                        break
                    else:
                        command += char.decode('utf-8')
                        channel.send(char)
                
                if command.strip() == 'exit':
                    break
                
                # Log commands
                self.logger.info(f"Command executed by {addr[0]}: {command.strip()}")
                
                # Simulate command output
                channel.send(f"bash: {command.strip()}: command not found\n")

        except Exception as e:
            self.logger.error(f"Error handling connection from {addr[0]}: {str(e)}")
        finally:
            try:
                transport.close()
            except:
                pass

    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            
            self.logger.info(f"SSH Honeypot listening on port {self.port}")
            
            while True:
                client, addr = server_socket.accept()
                self.logger.info(f"Connection from: {addr[0]}:{addr[1]}")
                
                thread = threading.Thread(target=self.handle_connection, args=(client, addr))
                thread.daemon = True
                thread.start()

        except Exception as e:
            self.logger.error(f"Error starting server: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    server = SSHServer()
    server.start()