#!/usr/bin/env python3
"""
Boot Menu for Honeypot System
Displays menu with options to start honeypot or view connection info
"""

import os
import sys
import platform
import secrets
import string
import json

def clear_screen():
    """Clear the terminal screen"""
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def print_banner():
    """Print the honeypot banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        ██████╗  ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗       ║
║        ██╔══██╗██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔══██╗      ║
║        ██████╔╝██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝      ║
║        ██╔═══╝ ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔═══╝       ║
║        ██║     ╚██████╔╝██║ ╚████║███████╗╚██████╔╝██║           ║
║        ╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝           ║
║                                                                  ║
║                   🍯  H O N E Y P O T   S Y S T E M  🍯          ║
║                 Intelligent Security Monitoring System           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_menu():
    """Print the main menu"""
    print("\n" + "="*60)
    print("  MAIN MENU")
    print("="*60)
    print("\n  1. Open Honeypot")
    print("  2. Encrypted Honeypot")
    print("  3. Exit")
    print("\n" + "="*60)

def get_user_choice():
    """Get user's menu choice"""
    while True:
        try:
            choice = input("\n  Enter your choice (1-3): ").strip()
            if choice in ['1', '2', '3']:
                return choice
            else:
                print("  [!] Invalid choice. Please enter 1, 2, or 3.")
        except (KeyboardInterrupt, EOFError):
            print("\n\n  [!] Exiting...")
            return '3'

def generate_secure_password(length=16):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def generate_encrypted_password():
    """Generate encrypted password in format honeypot@XXXX where XXXX is 4 random digits"""
    random_digits = ''.join(secrets.choice(string.digits) for i in range(4))
    return f"honeypot@{random_digits}"

def get_ip_address():
    """Get the local IP address"""
    ip_address = "localhost"
    try:
        import socket
        # Try to get local IP by connecting to external address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to external address (doesn't actually send data)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        except:
            # Fallback: try to get hostname IP
            try:
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                # If it's 127.0.0.1, try alternative method
                if ip_address == "127.0.0.1":
                    raise Exception("Localhost detected")
            except:
                pass
        finally:
            s.close()
    except:
        # Try platform-specific methods
        if platform.system() != 'Windows':
            try:
                import subprocess
                # Try multiple methods
                for cmd in [['hostname', '-I'], ['ip', 'addr', 'show'], ['ifconfig']]:
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            # Parse IP from output
                            output = result.stdout
                            import re
                            # Look for IPv4 addresses (not 127.0.0.1)
                            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output)
                            for ip in ips:
                                if not ip.startswith('127.'):
                                    ip_address = ip
                                    break
                            if ip_address != "localhost":
                                break
                    except:
                        continue
            except:
                pass
    return ip_address

def start_encrypted_honeypot():
    """Start the honeypot services with encrypted password"""
    clear_screen()
    print_banner()
    
    print("\n" + "="*60)
    print("  ENCRYPTED HONEYPOT SETUP & START")
    print("="*60)
    
    # Generate encrypted password in format honeypot@XXXX
    print("\n  [*] Generating encrypted password for SSH server...")
    ssh_password = generate_encrypted_password()
    
    # Save password to config file
    config_dir = 'config'
    os.makedirs(config_dir, exist_ok=True)
    password_file = os.path.join(config_dir, 'ssh_password.json')
    
    password_data = {
        'username': 'admin',
        'password': ssh_password,
        'encrypted_mode': True,
        'generated_at': None
    }
    
    try:
        from datetime import datetime
        password_data['generated_at'] = datetime.now().isoformat()
    except:
        pass
    
    # Save password to file
    try:
        with open(password_file, 'w') as f:
            json.dump(password_data, f, indent=2)
        print(f"  [+] Encrypted password saved: {ssh_password}")
    except Exception as e:
        print(f"  [!] Error saving password: {e}")
        return
    
    # Get IP address
    ip_address = get_ip_address()
    
    # Display connection information
    print("\n" + "="*60)
    print("  🔐 ENCRYPTED SSH HONEYPOT CONNECTION")
    print("="*60)
    print("\n  ⚠️  IMPORTANT: Save this password securely!")
    print("\n  📋 Connection Details:")
    print(f"     Command:  ssh -p 2222 admin@{ip_address}")
    print(f"     Username: admin")
    print(f"     Password: {ssh_password}")
    print("\n  🔒 Security:")
    print("     - Password format: honeypot@XXXX (4 random digits)")
    print("     - Password is saved in: config/ssh_password.json")
    print("     - Only this password will be accepted for SSH connections")
    
    print("\n  📊 Dashboard Access:")
    dashboard_username = os.environ.get('DASHBOARD_USERNAME', 'admin')
    dashboard_password = os.environ.get('DASHBOARD_PASSWORD', 'honeypot@91771')
    print(f"     URL:      http://{ip_address}:5001")
    print(f"     Username: {dashboard_username}")
    print(f"     Password: {dashboard_password}")
    
    print("\n" + "="*60)
    print("  STARTING ENCRYPTED HONEYPOT SERVICES...")
    print("="*60)
    print("\n  [*] This will start all honeypot services with encrypted password.")
    print("  [*] Press Ctrl+C to stop all services.\n")
    
    # Import and run the startup logic
    import subprocess
    import sys
    
    # Determine which startup script to use with --skip-menu flag
    if platform.system() == 'Windows':
        script = 'start.ps1'
        cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script, '-SkipMenu']
    else:
        script = 'start.sh'
        cmd = ['bash', script, '--skip-menu']
    
    try:
        # Run the startup script with skip menu flag
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n\n  [!] Honeypot services stopped.")
        print("  [*] Returning to main menu...\n")
        input("  Press Enter to continue...")
    except subprocess.CalledProcessError as e:
        print(f"\n  [!] Error starting honeypot: {e}")
        input("  Press Enter to return to main menu...")
    except FileNotFoundError:
        print(f"\n  [!] Startup script '{script}' not found.")
        print("  [*] Please run the startup script manually.")
        input("  Press Enter to return to main menu...")

def start_honeypot():
    """Start the honeypot services"""
    clear_screen()
    print_banner()
    print("\n" + "="*60)
    print("  STARTING HONEYPOT SERVICES...")
    print("="*60)
    print("\n  [*] This will start all honeypot services.")
    print("  [*] Press Ctrl+C to stop all services.\n")
    
    # Import and run the startup logic
    import subprocess
    import sys
    
    # Determine which startup script to use with --skip-menu flag
    if platform.system() == 'Windows':
        script = 'start.ps1'
        cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script, '-SkipMenu']
    else:
        script = 'start.sh'
        cmd = ['bash', script, '--skip-menu']
    
    try:
        # Run the startup script with skip menu flag
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n\n  [!] Honeypot services stopped.")
        print("  [*] Returning to main menu...\n")
        input("  Press Enter to continue...")
    except subprocess.CalledProcessError as e:
        print(f"\n  [!] Error starting honeypot: {e}")
        input("  Press Enter to return to main menu...")
    except FileNotFoundError:
        print(f"\n  [!] Startup script '{script}' not found.")
        print("  [*] Please run the startup script manually.")
        input("  Press Enter to return to main menu...")

def main():
    """Main menu loop"""
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        choice = get_user_choice()
        
        if choice == '1':
            start_honeypot()
        elif choice == '2':
            start_encrypted_honeypot()
        elif choice == '3':
            clear_screen()
            print_banner()
            print("\n  [*] Thank you for using Honeypot System!")
            print("  [*] Goodbye!\n")
            sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Exiting...")
        sys.exit(0)

