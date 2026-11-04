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

REM Activate and install Python dependencies
echo [*] Installing Python dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt

REM ── Install Scoop (package manager for the security tools) ───────────────
where scoop >nul 2>&1
if errorlevel 1 (
    echo [*] Installing Scoop package manager ^(no admin required^)...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb get.scoop.sh | iex"
    REM Scoop just added its shims to the user PATH; make them usable in THIS session too
    set "PATH=%USERPROFILE%\scoop\shims;%PATH%"
) else (
    echo [+] Scoop found.
)

REM ── Payload-execution tools via Scoop (native Windows binaries) ──────────
echo [*] Installing payload tools: nmap, gobuster, ffuf, nuclei...
call scoop install nmap gobuster ffuf nuclei

REM ── sqlmap via pip (pure-Python, installed into the venv) ────────────────
echo [*] Installing sqlmap...
pip install sqlmap

echo.
echo [+] Setup complete.
echo.
echo  Installed exploit tools: nmap, sqlmap, gobuster, ffuf, nuclei ^(curl is built in^).
echo.
echo  Notes:
echo  - nmap runs in connect^(^) mode. For raw-packet scans install Npcap once as admin:
echo        "%%USERPROFILE%%\scoop\apps\nmap\current\npcap.exe"
echo  - nikto, dirb, hydra and whatweb have no native Windows build.
echo    If you need them, run ARGOS tools inside WSL or install them there.
echo.
echo  Next steps:
echo  1. Start your llama-server:
echo        llama-server -m your-model.gguf --port 8080 -c 16384
echo  2. Edit config.py if your server uses a different port or model name
echo  3. Run start.bat to launch ARGOS
echo.
pause
