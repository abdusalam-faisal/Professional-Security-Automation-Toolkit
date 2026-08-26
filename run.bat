@echo off
title Security Automation Toolkit v3
cd /d "%~dp0"
python -m pip install --quiet -r requirements.txt
python main.py
pause
