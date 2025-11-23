#!/bin/bash
# Linux/Mac launcher for Honeypot Boot Menu

# Detect Python
if command -v python3 >/dev/null 2>&1; then
    python3 boot_menu.py
elif command -v python >/dev/null 2>&1; then
    python boot_menu.py
else
    echo "Python not found. Please install Python 3.8 or higher."
    exit 1
fi

