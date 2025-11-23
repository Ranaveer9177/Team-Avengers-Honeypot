@echo off
REM Windows launcher for Honeypot Boot Menu
python boot_menu.py
if errorlevel 1 (
    echo Python not found. Please install Python 3.8 or higher.
    pause
)

