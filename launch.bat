@echo off
REM Windows launcher for Honeypot Boot Menu
REM VULN-043 FIX: Check Python version before launching

REM Try py -3 launcher first (recommended on Windows)
py -3 --version >nul 2>&1
if %errorlevel% equ 0 (
    py -3 boot_menu.py
    goto :end
)

REM Fallback to python and verify it's Python 3
python --version 2>&1 | findstr /R "Python 3\." >nul
if %errorlevel% equ 0 (
    python boot_menu.py
    goto :end
)

echo Python 3.x is required but not found.
echo Please install Python 3.8 or higher from https://www.python.org/downloads/
pause

:end
