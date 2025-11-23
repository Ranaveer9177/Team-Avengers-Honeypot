# 🍯 Honeypot Boot Menu Guide

## Overview

The Honeypot system now includes an interactive boot menu that displays when you start the system. This menu provides easy access to start the honeypot services and view connection information.

## Features

- **Interactive Menu**: Clean, user-friendly interface with banner display
- **Quick Start**: Option to start all honeypot services with one selection
- **Connection Info**: View all connection details, passwords, and IP addresses
- **Cross-Platform**: Works on both Windows and Linux/Mac systems

## Usage

### Starting the Boot Menu

**Windows:**
```powershell
# Option 1: Run the boot menu directly
python boot_menu.py

# Option 2: Use the launcher
.\launch.bat

# Option 3: Run start script (shows menu automatically)
.\start.ps1
```

**Linux/Mac:**
```bash
# Option 1: Run the boot menu directly
python3 boot_menu.py

# Option 2: Use the launcher
./launch.sh

# Option 3: Run start script (shows menu automatically)
./start.sh
```

### Menu Options

1. **Open Honeypot** - Starts all honeypot services (SSH, HTTP, HTTPS, FTP, MySQL, Dashboard)
2. **Password to Connect to Server** - Displays all connection information including:
   - Dashboard URL, username, and password
   - SSH connection details
   - Web service URLs
   - FTP and MySQL connection info
   - Current IP address
3. **Exit** - Closes the boot menu

### Skipping the Menu

If you want to start the honeypot directly without the menu:

**Windows:**
```powershell
.\start.ps1 -SkipMenu
```

**Linux/Mac:**
```bash
./start.sh --skip-menu
```

## Menu Display

When the system boots, you'll see:

```
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║                    🍯  HONEYPOT  🍯                       ║
    ║                                                           ║
    ║              Security Monitoring System                  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝

    ============================================================
      MAIN MENU
    ============================================================

      1. Open Honeypot
      2. Password to Connect to Server
      3. Exit

    ============================================================
```

## Connection Information Display

When you select option 2, you'll see detailed connection information:

- **Dashboard Access**: Web interface URL, username, and password
- **SSH Honeypot**: Connection command, username, and password policy
- **Web Services**: HTTP and HTTPS URLs
- **Other Services**: FTP and MySQL connection details
- **IP Address**: Automatically detected local IP address

## Notes

- The boot menu automatically detects your system's IP address
- All connection information is pulled from environment variables or defaults
- The menu will return after stopping honeypot services (Ctrl+C)
- The menu is designed to be user-friendly and intuitive

## Troubleshooting

**Menu doesn't appear:**
- Ensure Python 3.8+ is installed
- Check that `boot_menu.py` is in the project directory
- Try running `python boot_menu.py` directly

**IP address shows as "localhost":**
- This is normal if the system can't detect the network IP
- You can manually replace "localhost" with your actual IP when connecting

**Services don't start:**
- Check that all required Python packages are installed
- Verify that required ports (2222, 5001, 8080, 8443, 2121, 3306) are available
- Review the startup script output for error messages

