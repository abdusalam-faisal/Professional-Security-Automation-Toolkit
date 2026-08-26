#!/usr/bin/env bash
# Security Automation Toolkit - Linux/macOS launcher
cd "$(dirname "$0")"
python3 -m pip install --quiet -r requirements.txt
python3 main.py
