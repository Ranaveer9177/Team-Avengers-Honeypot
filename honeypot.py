#!/usr/bin/env python3
import paramiko
import socket
import threading
import logging
import json
import datetime
from pathlib import Path
from binascii import hexlify

# New import for HTTP push
try:
    import requests
except Exception:
    requests = None

# Configuration
HONEYPOT_HOST = '0.0.0.0'
HONEYPOT_PORT = 2222
LOG_DIR = Path("honeypot_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Concurrency limit
MAX_CONCURRENT_CONNECTIONS = 5
_connection_semaphore = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)

# Dashboard receiver
DASHBOARD_URL = "http://127.0.0.1:5000/api/event"

# SSH Banner to appear legitimate
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

# Generate or load server key
try:
    HOST_KEY = paramiko.RSAKey(filename='server.key')
except Exception:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file('server.key')

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename=LOG_DIR / 'ssh_honeypot.log'
)


class SSHHoneypot(paramiko.ServerInterface):
    """SSH Honeypot that logs all attacker interactions"""

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        logging.info(f'Channel request ({self.client_ip}): {kind}')
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        self.username = username
        logging.info(f'Auth methods requested ({self.client_ip}): username={username}')
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        logging.info(f'Login attempt ({self.client_ip}): {username}:{password}')
        attack = log_attack(self.client_ip, username, password, 'password')
        notify_new_attack(attack)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        fingerprint = hexlify(key.get_fingerprint()).decode('ascii')
        logging.info(f'Public key auth ({self.client_ip}): {username}, fingerprint={fingerprint}')
        attack = log_attack(self.client_ip, username, fingerprint, 'publickey')
        notify_new_attack(attack)
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = command.decode('utf-8', errors='ignore')
        logging.info(f'Command executed ({self.client_ip}): {command_text}')
        cmd_ev = log_command(self.client_ip, self.username, command_text)
        notify_new_attack(cmd_ev)
        return True


def log_attack(ip, username, credential, auth_type):
    attack_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'ip': ip,
        'username': username,
        'credential': credential,
        'auth_type': auth_type,
        'event_type': 'login_attempt'
    }
    json_log = LOG_DIR / f"attacks_{datetime.date.today()}.json"
    with open(json_log, 'a', encoding='utf-8') as f:
        json.dump(attack_data, f)
        f.write('\n')
    return attack_data


def log_command(ip, username, command):
    command_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'ip': ip,
        'username': username,
        'command': command,
        'event_type': 'command_execution'
    }
    json_log = LOG_DIR / f"commands_{datetime.date.today()}.json"
    with open(json_log, 'a', encoding='utf-8') as f:
        json.dump(command_data, f)
        f.write('\n')
    return command_data


def handle_cmd(cmd, chan, ip):
    response = ""
    cmd = cmd.strip()

    if cmd.startswith("ls"):
        response = "bin  boot  dev  etc  home  lib  root  usr  var"
    elif cmd.startswith("pwd"):
        response = "/home/ubuntu"
    elif cmd.startswith("whoami"):
        response = "ubuntu"
    elif cmd.startswith("uname"):
        response = "Linux ubuntu 5.4.0-42-generic x86_64 GNU/Linux"
    elif cmd.startswith("cat /etc/passwd"):
        response = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash"
    elif cmd.startswith("id"):
        response = "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)"
    else:
        response = f"bash: {cmd.split()[0]}: command not found"

    if response:
        chan.send(response + "\r\n")


def handle_connection(client_socket, client_addr):
    client_ip = client_addr[0]
    logging.info(f'New connection from: {client_ip}')

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER

        server = SSHHoneypot(client_ip)

        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            logging.error(f'SSH negotiation failed for {client_ip}')
            return

        chan = transport.accept(20)
        if chan is None:
            logging.warning(f'No channel opened by {client_ip}')
            return

        if transport.remote_version:
            logging.info(f'Client SSH version ({client_ip}): {transport.remote_version}')

        server.event.wait(10)
        if not server.event.is_set():
            logging.info(f'Client {client_ip} did not request shell')
            return

        chan.send("Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n")

        run = True
        while run:
            chan.send("$ ")
            command = ""
            while not command.endswith("\r"):
                try:
                    data = chan.recv(1024)
                    if not data:
                        run = False
                        break
                    chan.send(data)
                    command += data.decode('utf-8', errors='ignore')
                except Exception:
                    run = False
                    break
            if not run:
                break
            command = command.strip()
            if command:
                logging.info(f'Command from {client_ip}: {command}')
                cmd_ev = log_command(client_ip, server.username, command)
                notify_new_attack(cmd_ev)
                if command == "exit":
                    chan.send("logout\r\n")
                    run = False
                else:
                    handle_cmd(command, chan, client_ip)

    except Exception as e:
        logging.error(f'Error handling connection from {client_ip}: {e}')
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        # Release slot for the next connection
        try:
            _connection_semaphore.release()
        except Exception:
            pass


def start_honeypot():
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HONEYPOT_HOST, HONEYPOT_PORT))
        sock.listen(100)
        print(f'[*] SSH Honeypot listening on {HONEYPOT_HOST}:{HONEYPOT_PORT}')
        print(f'[*] Logs saved to {LOG_DIR}')
        while True:
            # Enforce connection concurrency limit
            _connection_semaphore.acquire()
            client, addr = sock.accept()
            client_thread = threading.Thread(
                target=handle_connection,
                args=(client, addr),
                daemon=True
            )
            client_thread.start()
    except Exception as e:
        logging.error(f'Server error: {e}')
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


# Send real-time notification to dashboard
def notify_new_attack(attack_data):
    if requests is None:
        return
    try:
        requests.post(DASHBOARD_URL, json=attack_data, timeout=1.5)
    except Exception:
        pass


if __name__ == '__main__':
    start_honeypot()
