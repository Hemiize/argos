@echo off
title ARGOS
cd /d "%~dp0"
call venv\Scripts\activate.bat
python argos.py
