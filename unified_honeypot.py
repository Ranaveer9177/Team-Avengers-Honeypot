import socket
import threading
import paramiko
import logging
import json
import ssl
import time
from datetime import datetime, timezone
import os
import secrets
import string
from socket import gethostbyaddr, herror
import shlex
from device_detector import DeviceDetector

class FakeFileSystem:
    """Simulates a realistic Ubuntu filesystem for the honeypot"""
    
    def __init__(self):
        self.current_dir = '/home/admin'
        self.filesystem = {
            '/': {
                'type': 'directory',
                'contents': {
                    'home': {
                        'type': 'directory',
                        'contents': {
                            'admin': {
                                'type': 'directory',
                                'contents': {
                    'Documents': {'type': 'directory', 'contents': {
                        'project1': {'type': 'file', 'content': 'Project documentation and notes.\n'},
                        'meeting_notes.txt': {'type': 'file', 'content': 'Meeting notes from last week.\n'},
                        'backup': {'type': 'directory', 'contents': {}}
                    }},
                    'Downloads': {'type': 'directory', 'contents': {
                        'file1.pdf': {'type': 'file', 'content': 'PDF document content.\n'},
                        'image.jpg': {'type': 'file', 'content': 'Image file (binary data)\n'},
                        'archive.tar.gz': {'type': 'file', 'content': 'Compressed archive\n'}
                    }},
                    'Desktop': {'type': 'directory', 'contents': {
                        'notes.txt': {'type': 'file', 'content': 'Quick notes\n'},
                        'screenshot.png': {'type': 'file', 'content': 'Screenshot image\n'}
                    }},
                    '.bashrc': {'type': 'file', 'content': '# ~/.bashrc: executed by bash(1) for non-login shells.\n# See /usr/share/doc/bash/examples/startup-files (in the package bash-doc)\n'},
                    '.bash_history': {'type': 'file', 'content': 'cd Documents\nls -la\ncat notes.txt\n'},
                    '.ssh': {'type': 'directory', 'contents': {
                        'id_rsa.pub': {'type': 'file', 'content': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... admin@ubuntu\n'}
                    }}
                                }
                            }
                        }
                    },
                    'etc': {
                        'type': 'directory',
                        'contents': {
                            'passwd': {'type': 'file', 'content': 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'},
                            'hosts': {'type': 'file', 'content': '127.0.0.1\tlocalhost\n127.0.1.1\tubuntu-server\n'},
                            'hostname': {'type': 'file', 'content': 'ubuntu-server\n'},
                            'os-release': {'type': 'file', 'content': 'NAME="Ubuntu"\nVERSION="20.04.3 LTS (Focal Fossa)"\nID=ubuntu\n'}
                        }
                    },
                    'var': {
                        'type': 'directory',
                        'contents': {
                            'log': {'type': 'directory', 'contents': {
                                'syslog': {'type': 'file', 'content': 'System log entries...\n'},
                                'auth.log': {'type': 'file', 'content': 'Authentication log entries...\n'}
                            }}
                        }
                    },
                    'tmp': {
                        'type': 'directory',
                        'contents': {
                            'temp_file.txt': {'type': 'file', 'content': 'Temporary file content\n'}
                        }
                    }
                }
            }
        }
    
    def normalize_path(self, path):
        """Normalize a path relative to current directory"""
        if path.startswith('/'):
            return path
        if self.current_dir == '/':
            return '/' + path
        return self.current_dir.rstrip('/') + '/' + path
    
    def get_path_parts(self, path):
        """Split path into parts"""
        normalized = self.normalize_path(path)
        parts = [p for p in normalized.split('/') if p]
        return ['/'] + parts if normalized.startswith('/') else parts
    
    def get_item(self, path):
        """Get filesystem item at path (directory contents)"""
        parts = self.get_path_parts(path)
        if not parts:
            return None
        
        # Start from root
        current = self.filesystem.get('/', {}).get('contents', {})
        
        # Handle root directory
        if parts == ['/'] or (len(parts) == 1 and parts[0] == '/'):
            return current
        
        # Remove leading '/' if present
        if parts[0] == '/':
            parts = parts[1:]
        
        # Navigate through directories
        for i, part in enumerate(parts):
            if part in current:
                if current[part]['type'] == 'directory':
                    if i == len(parts) - 1:
                        # This is the target directory
                        return current[part].get('contents', {})
                    current = current[part].get('contents', {})
                else:
                    # Hit a file before reaching target
                    return None
            else:
                return None
        return current
    
    def list_directory(self, path='.'):
        """List directory contents"""
        if path == '.':
            path = self.current_dir
        
        target = self.get_item(path)
        if target is None:
            return None
        
        items = []
        for name, item in target.items():
            if item['type'] == 'directory':
                items.append(name + '/')
            else:
                items.append(name)
        return sorted(items)
    
    def read_file(self, path):
        """Read file content"""
        parts = self.get_path_parts(path)
        if not parts or parts == ['/']:
            return None
        
        # Handle absolute paths
        if parts[0] == '/':
            parts = parts[1:]
        
        current = self.filesystem
        
        # Navigate to parent directory
        for i, part in enumerate(parts[:-1]):
            if part in current and current[part]['type'] == 'directory':
                current = current[part].get('contents', {})
            else:
                return None
        
        # Get the file
        filename = parts[-1]
        if filename in current and current[filename]['type'] == 'file':
            return current[filename].get('content', '')
        return None
    
    def change_directory(self, path):
        """Change current directory"""
        if path == '~' or path == '':
            self.current_dir = '/home/admin'
            return True
        
        normalized = self.normalize_path(path)
        if self.get_item(normalized):
            self.current_dir = normalized
            return True
        return False

class UnifiedHoneypot(paramiko.ServerInterface):
    def __init__(self, allowed_key=None):
        self.event = threading.Event()
        self.allowed_key = allowed_key
        self.filesystem = FakeFileSystem()
        
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
        print(f"Login attempt - Username: {username}, Password: {password}")
        
        # Accept ANY password for admin user - allows anyone to connect easily
        if username == "admin":
            self.event.set()  # Signal successful authentication
            print(f"[*] Authentication successful for admin (any password accepted)")
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
        
        # Rate limiting: Track connection attempts per IP
        self.connection_tracker = {}  # {ip: [timestamp1, timestamp2, ...]}
        self.max_connections_per_ip = 10  # Max connections per minute
        self.rate_limit_window = 60  # seconds
        
        # Connection timeout settings
        self.connection_timeout = 30  # seconds
        
        # SSH authentication: Accept ANY password for admin user
        # This allows anyone to connect with: ssh -p 2222 admin@IP
        print("\n" + "="*50)
        print(f"[!] SSH Honeypot Configuration")
        print(f"[!] Username: admin")
        print(f"[!] Password: ANY (accepts any password)")
        print(f"[!] Connection: ssh -p 2222 admin@YOUR_IP")
        print("="*50 + "\n")

    def load_config(self, config_file):
        default_config = {
            'ssh_port': 2222,
            'http_port': 8080,
            'https_port': 8443,
            'ftp_port': 2121,
            'mysql_port': 3306,
            'log_dir': 'logs',
            'ssh_key_dir': 'ssh_keys',
            'cert_dir': 'certs',
            'pcap_dir': 'pcaps',
            'pcap_enabled': True,
            'initial_payload_max_bytes': 512,
            'banners': {
                'ssh_version': 'SSH-2.0-OpenSSH_7.4',
                'http_server': 'Apache/2.4.41 (Ubuntu)'
            }
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
        # Ensure SSH key directory exists
        os.makedirs(self.config['ssh_key_dir'], exist_ok=True)
        
        key_path = os.path.join(self.config['ssh_key_dir'], 'server.key')
        
        # Generate SSH host key if missing (persist across restarts)
        if not os.path.exists(key_path):
            self.logger.info(f"Generating new SSH host key at {key_path}")
            try:
                # Generate 2048-bit RSA key using Paramiko
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(key_path)
                self.logger.info(f"SSH host key generated successfully")
            except Exception as e:
                self.logger.error(f"Error generating SSH host key: {str(e)}")
                raise
        
        # Load the existing or newly generated key
        try:
            self.host_key = paramiko.RSAKey(filename=key_path)
            self.logger.info(f"Loaded SSH host key from {key_path}")
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
        """Generate self-signed SSL certificate using OpenSSL or cryptography module"""
        cert_path = f"{self.config['cert_dir']}/server.crt"
        key_path = f"{self.config['cert_dir']}/server.key"
        
        try:
            # Try using OpenSSL command-line tool first
            import subprocess
            result = subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_path, '-out', cert_path,
                '-days', '365', '-nodes',
                '-subj', '/CN=localhost'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.info("Generated SSL certificate using OpenSSL")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.logger.warning(f"OpenSSL not available: {e}")
        
        # Fallback: Use cryptography module if OpenSSL not available
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Honeypot"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write private key
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.logger.info("Generated SSL certificate using cryptography module")
        except ImportError:
            self.logger.error("Neither OpenSSL nor cryptography module available. HTTPS will not work.")
            self.logger.error("Install with: pip install cryptography")
        except Exception as e:
            self.logger.error(f"Failed to generate SSL certificate: {e}")

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

    def get_device_name(self, ip, client_version=None):
        """Get device name using reverse DNS and optional client version detection"""
        try:
            hostname, _, _ = gethostbyaddr(ip)
            # If we have client version info, try to detect device type
            if client_version:
                detected = DeviceDetector.detect_device(client_version, 'ssh')
                return f"{hostname} ({detected})"
            return hostname
        except (herror, socket.error):
            if client_version:
                return DeviceDetector.detect_device(client_version, 'ssh')
            return "Unknown Device"

    def detect_tools(self, data):
        detected = []
        data_str = str(data).lower()
        
        for tool, signatures in self.tool_signatures.items():
            if any(sig.lower() in data_str for sig in signatures):
                detected.append(tool)
        
        return list(set(detected))
    
    def check_rate_limit(self, ip):
        """Check if IP has exceeded rate limit"""
        current_time = time.time()
        
        # Clean up old entries
        if ip in self.connection_tracker:
            self.connection_tracker[ip] = [
                ts for ts in self.connection_tracker[ip] 
                if current_time - ts < self.rate_limit_window
            ]
        else:
            self.connection_tracker[ip] = []
        
        # Check if over limit
        if len(self.connection_tracker[ip]) >= self.max_connections_per_ip:
            self.logger.warning(f"Rate limit exceeded for {ip}")
            return False
        
        # Add current connection
        self.connection_tracker[ip].append(current_time)
        return True

    def _utc_now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def _write_initial_payload(self, data_bytes, meta_prefix):
        try:
            os.makedirs(self.config['pcap_dir'], exist_ok=True)
            file_path = os.path.join(
                self.config['pcap_dir'], f"{meta_prefix}_initial.bin"
            )
            with open(file_path, 'ab') as f:
                f.write(data_bytes[: int(self.config.get('initial_payload_max_bytes', 512))])
        except Exception as e:
            self.logger.error(f"Error writing initial payload: {str(e)}")

    def _maybe_start_pcap_capture(self):
        if not self.config.get('pcap_enabled', True):
            return
        # Attempt to start tcpdump if available; ignore failures
        try:
            os.makedirs(self.config['pcap_dir'], exist_ok=True)
            ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            pcap_file = os.path.join(self.config['pcap_dir'], f"unified_{ts}.pcap")
            # Filter common honeypot ports
            ports = [
                str(self.config['ssh_port']), str(self.config['http_port']),
                str(self.config['https_port']), str(self.config['ftp_port']),
                str(self.config['mysql_port'])
            ]
            port_filter = ' or '.join([f"port {p}" for p in ports])
            import subprocess
            subprocess.Popen([
                'tcpdump', '-i', 'any', '-s', '0', '-w', pcap_file, port_filter
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.logger.info(f"pcap capture started: {pcap_file}")
        except Exception as e:
            self.logger.warning(f"pcap capture not started (tcpdump missing or permission issue): {str(e)}")

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
            # Set socket timeout
            client.settimeout(self.connection_timeout)
            
            # Check rate limit
            if not self.check_rate_limit(addr[0]):
                client.close()
                return
            
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            # Set a consistent SSH banner/version
            try:
                transport.local_version = self.config.get('banners', {}).get('ssh_version', 'SSH-2.0-OpenSSH_7.4')
            except Exception:
                pass
            
            honeypot = UnifiedHoneypot(self.config.get('allowed_key'))
            # No password check needed - accepts any password for admin
            honeypot.attack_details['ip'] = addr[0]
            honeypot.attack_details['device_name'] = self.get_device_name(addr[0])
            honeypot.attack_details['timestamp'] = self._utc_now_iso()
            
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
            
            # Initialize filesystem for this session
            fs = FakeFileSystem()
            
            # Interactive shell loop
            while True:
                channel.send('$ ')
                command = ''
                try:
                    while True:
                        char = channel.recv(1)
                        if not char:
                            break
                        if char == b'\r' or char == b'\n':
                            channel.send(b'\n')
                            break
                        elif char == b'\x03':  # Ctrl+C
                            channel.send(b'^C\n')
                            command = ''
                            break
                        elif char == b'\x7f' or char == b'\x08':  # Backspace
                            if len(command) > 0:
                                command = command[:-1]
                                channel.send(b'\b \b')
                        else:
                            command += char.decode('utf-8', errors='ignore')
                            channel.send(char)
                except Exception as e:
                    print(f"Error reading command: {str(e)}")
                    break
                
                if not char:  # Connection closed
                    break
                
                command = command.strip()
                if not command:
                    continue
                
                if command == 'exit':
                    channel.send('logout\n')
                    break

                # Log commands for analysis
                print(f"[*] Command executed: {command}")
                
                # Parse command
                try:
                    parts = shlex.split(command)
                    cmd = parts[0] if parts else ''
                    args = parts[1:] if len(parts) > 1 else []
                except:
                    cmd = command.split()[0] if command.split() else ''
                    args = command.split()[1:] if len(command.split()) > 1 else []
                
                # Handle commands
                handled = False
                
                if cmd == 'whoami':
                    channel.send('admin\n')
                    handled = True
                elif cmd == 'id':
                    channel.send('uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)\n')
                    handled = True
                elif cmd == 'pwd':
                    channel.send(f"{fs.current_dir}\n")
                    handled = True
                elif cmd == 'ls':
                    path = args[0] if args else '.'
                    if '-la' in args or '-l' in args or '-a' in args:
                        # Detailed listing
                        items = fs.list_directory(path)
                        if items:
                            output = 'total 24\n'
                            for item in items:
                                if item.endswith('/'):
                                    output += f'drwxr-xr-x 2 admin admin 4096 Jan 15 10:30 {item}\n'
                                else:
                                    output += f'-rw-r--r-- 1 admin admin  1024 Jan 15 10:30 {item}\n'
                            channel.send(output)
                        else:
                            channel.send(f"ls: cannot access '{path}': No such file or directory\n")
                    else:
                        items = fs.list_directory(path)
                        if items:
                            channel.send(' '.join(items) + '\n')
                        else:
                            channel.send(f"ls: cannot access '{path}': No such file or directory\n")
                    handled = True
                elif cmd == 'cd':
                    target = args[0] if args else '~'
                    if fs.change_directory(target):
                        # Success, no output
                        pass
                    else:
                        channel.send(f"bash: cd: {target}: No such file or directory\n")
                    handled = True
                elif cmd == 'cat':
                    if args:
                        for filepath in args:
                            content = fs.read_file(filepath)
                            if content:
                                channel.send(content)
                            else:
                                channel.send(f"cat: {filepath}: No such file or directory\n")
                    else:
                        channel.send("cat: missing file argument\n")
                    handled = True
                elif cmd == 'uname':
                    if '-a' in args:
                        channel.send('Linux ubuntu-server 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\n')
                    else:
                        channel.send('Linux\n')
                    handled = True
                elif cmd == 'hostname':
                    channel.send('ubuntu-server\n')
                    handled = True
                elif cmd == 'echo':
                    channel.send(' '.join(args) + '\n')
                    handled = True
                elif cmd == 'clear' or cmd == 'reset':
                    channel.send('\033[2J\033[H')  # ANSI clear screen
                    handled = True
                elif cmd.startswith('./') or cmd.startswith('/'):
                    # Try to execute script
                    channel.send(f"bash: {cmd}: Permission denied\n")
                    handled = True
                
                if not handled:
                    channel.send(f"bash: {cmd}: command not found\n")

                # Detect tools from command
                tools = self.detect_tools(command)
                if tools:
                    honeypot.attack_details['tools_detected'].extend(tools)
                    self.log_attack(honeypot.attack_details)

        except Exception as e:
            self.logger.error(f"SSH Error from {addr[0]}: {str(e)}")
        finally:
            try:
                transport.close()
            except:
                pass

    def handle_ftp_connection(self, client_socket, addr):
        """Handle FTP honeypot connections"""
        try:
            # Set socket timeout
            client_socket.settimeout(self.connection_timeout)
            
            # Check rate limit
            if not self.check_rate_limit(addr[0]):
                client_socket.close()
                return
            
            # Send FTP welcome banner
            client_socket.send(b"220 Welcome to FTP Server\r\n")
            
            data = client_socket.recv(4096)
            if data:
                # Save initial payload
                meta = f"{self._utc_now_iso()}_{addr[0]}_ftp"
                safe_meta = meta.replace(':', '').replace('/', '').replace('\\', '')
                self._write_initial_payload(data, safe_meta)
                
                request = data.decode('utf-8', errors='ignore')
                
                # Parse FTP commands
                commands = request.strip().split('\r\n')
                username = None
                password = None
                
                for cmd in commands:
                    if cmd.upper().startswith('USER '):
                        username = cmd[5:].strip()
                        client_socket.send(b"331 Password required\r\n")
                    elif cmd.upper().startswith('PASS '):
                        password = cmd[5:].strip()
                        client_socket.send(b"530 Login incorrect\r\n")
                        
                        # Log the attack with device detection
                        device = DeviceDetector.detect_device(data, 'ftp')
                        attack_details = {
                            'ip': addr[0],
                            'device_name': device,
                            'timestamp': self._utc_now_iso(),
                            'service': 'ftp',
                            'username': username or 'anonymous',
                            'password': password or '',
                            'tools_detected': self.detect_tools(data),
                            'attack_type': 'ftp_brute_force'
                        }
                        self.log_attack(attack_details)
                    elif cmd.upper().startswith('QUIT'):
                        client_socket.send(b"221 Goodbye\r\n")
                        break
                    else:
                        client_socket.send(b"500 Unknown command\r\n")
        except Exception as e:
            self.logger.error(f"FTP Error from {addr[0]}: {str(e)}")
        finally:
            client_socket.close()

    def handle_mysql_connection(self, client_socket, addr):
        """Handle MySQL honeypot connections"""
        try:
            # Set socket timeout
            client_socket.settimeout(self.connection_timeout)
            
            # Check rate limit
            if not self.check_rate_limit(addr[0]):
                client_socket.close()
                return
            
            # MySQL handshake packet (simplified version)
            # Protocol version 10, server version 5.7.0
            handshake = b'\x4a\x00\x00\x00\x0a' \
                       b'5.7.0\x00' \
                       b'\x01\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00'
            
            client_socket.send(handshake)
            
            data = client_socket.recv(4096)
            if data:
                # Save initial payload
                meta = f"{self._utc_now_iso()}_{addr[0]}_mysql"
                safe_meta = meta.replace(':', '').replace('/', '').replace('\\', '')
                self._write_initial_payload(data, safe_meta)
                
                # Log the connection attempt with device detection
                device = DeviceDetector.detect_device(data, 'mysql')
                attack_details = {
                    'ip': addr[0],
                    'device_name': device,
                    'timestamp': self._utc_now_iso(),
                    'service': 'mysql',
                    'data': data.hex()[:200],  # Store hex representation
                    'tools_detected': self.detect_tools(data),
                    'attack_type': 'mysql_connection_attempt'
                }
                self.log_attack(attack_details)
                
                # Send access denied
                error_packet = b'\x17\x00\x00\x02\xff\x15\x04#28000Access denied'
                client_socket.send(error_packet)
        except Exception as e:
            self.logger.error(f"MySQL Error from {addr[0]}: {str(e)}")
        finally:
            client_socket.close()

    def handle_web_connection(self, client_socket, addr, is_https=False):
        try:
            # Set socket timeout
            client_socket.settimeout(self.connection_timeout)
            
            # Check rate limit
            if not self.check_rate_limit(addr[0]):
                client_socket.close()
                return
            
            if is_https:
                client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)

            data = client_socket.recv(4096)
            if data:
                # Save initial payload
                meta = f"{self._utc_now_iso()}_{addr[0]}_{'https' if is_https else 'http'}"
                safe_meta = meta.replace(':', '').replace('/', '').replace('\\', '')
                self._write_initial_payload(data, safe_meta)

                request = data.decode('utf-8', errors='ignore')
                lines = request.split('\r\n')
                method = lines[0].split()[0] if lines and lines[0] else 'UNKNOWN'
                path = lines[0].split()[1] if lines and len(lines[0].split()) > 1 else '/'

                # Parse POST data if present
                post_data = {}
                response_body = None
                
                if method == 'POST' and '/login' in path:
                    body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''
                    post_data = {}
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            post_data[key] = value
                    
                    # Log login attempts with device detection
                    if 'username' in post_data and 'password' in post_data:
                        device = DeviceDetector.detect_device(data, 'https' if is_https else 'http')
                        attack_details = {
                            'ip': addr[0],
                            'device_name': device,
                            'timestamp': self._utc_now_iso(),
                            'service': 'https' if is_https else 'http',
                            'username': post_data['username'],
                            'password': post_data['password'],
                            'tools_detected': self.detect_tools(data),
                            'attack_type': 'brute_force_web'
                        }
                        self.log_attack(attack_details)
                        
                        # Get template and insert error message
                        try:
                            with open('templates/login.html', 'r') as f:
                                template = f.read()
                        except FileNotFoundError:
                            # Fallback if template doesn't exist
                            template = '<html><body><h1>Login</h1><form method="POST"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button type="submit">Login</button></form></body></html>'
                        
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
                
                # For GET requests, non-login POST, or if response_body not set
                if response_body is None:
                    try:
                        with open('templates/login.html', 'r') as f:
                            response_body = f.read().replace('{% if error %}', '').replace('{% endif %}', '')
                    except FileNotFoundError:
                        # Fallback if template doesn't exist
                        response_body = '<html><body><h1>Login</h1><form method="POST" action="/login"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button type="submit">Login</button></form></body></html>'
                    
                    if method != 'POST':
                        device = DeviceDetector.detect_device(data, 'https' if is_https else 'http')
                        attack_details = {
                            'ip': addr[0],
                            'device_name': device,
                            'timestamp': self._utc_now_iso(),
                            'service': 'https' if is_https else 'http',
                            'data': request,
                            'tools_detected': self.detect_tools(data),
                            'attack_type': 'web_request'
                        }
                        self.log_attack(attack_details)

                # Ensure response_body is set
                if response_body is None:
                    response_body = '<html><body><h1>Service Unavailable</h1></body></html>'

                response = "HTTP/1.1 200 OK\r\n"
                response += f"Server: {self.config.get('banners', {}).get('http_server', 'Apache/2.4.41 (Ubuntu)')}\r\n"
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
            
            # Route to appropriate handler based on service type
            if service_type == 'ssh':
                handler = self.handle_ssh_connection
                args = (client, addr)
            elif service_type == 'ftp':
                handler = self.handle_ftp_connection
                args = (client, addr)
            elif service_type == 'mysql':
                handler = self.handle_mysql_connection
                args = (client, addr)
            else:  # http or https
                handler = self.handle_web_connection
                args = (client, addr, service_type == 'https')
            
            thread = threading.Thread(target=handler, args=args)
            thread.daemon = True
            thread.start()

    def start(self):
        services = ['ssh', 'http', 'https', 'ftp', 'mysql']
        # Try to start full PCAP capture
        self._maybe_start_pcap_capture()

        for service in services:
            thread = threading.Thread(target=self.start_service, args=(service,))
            thread.daemon = True
            thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down unified honeypot...")

def main():
    """Main entry point for honeypot server"""
    try:
        server = UnifiedHoneypotServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot server...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()