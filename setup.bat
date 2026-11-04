@echo off
title ARGOS Setup
echo.
echo  ARGOS - Web Security Analysis Assistant
echo  ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Install from https://python.org
    pause & exit /b 1
)
echo [+] Python found.

REM Create venv
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

REM Activate and install
echo [*] Installing Python dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo.
echo [+] Setup complete.
echo.
echo  Next steps:
echo  1. Install nmap from https://nmap.org/download.html  (add to PATH)
echo  2. Start your llama-server:
echo       llama-server -m your-model.gguf --port 8080 -c 16384
echo  3. Edit config.py if your server uses a different port or model name
echo  4. Run start.bat to launch ARGOS
echo.
pause
