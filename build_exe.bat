@echo off
title Build Security Toolkit EXE
cd /d "%~dp0"
python -m pip install --quiet pyinstaller
pyinstaller --onefile --windowed --name SecurityToolkit --icon=security.ico main.py
echo.
echo Build finished. Check the "dist" folder for SecurityToolkit.exe
pause
