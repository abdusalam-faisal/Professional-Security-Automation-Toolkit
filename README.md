# 🔒 Professional Security Automation Toolkit (v3.0)

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![GUI Framework](https://img.shields.io/badge/GUI-Tkinter-green.svg)](https://docs.python.org/3/library/tkinter.html)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](#ethical-usage)

## 📋 Overview

**Professional Security Automation Toolkit** is a comprehensive Python-based cybersecurity assessment platform that integrates 9 specialized security analysis modules into a unified, responsive Graphical User Interface (GUI). 

Designed for security researchers, students, and authorized penetration testers, the toolkit automates network analysis, web vulnerability auditing, log parsing, cryptography verification, and live traffic inspection under strict ethical boundaries.

> 🚨 **Disclaimer:** For educational purposes and authorized security testing only. Do not execute tools against unauthorized systems.

---

## ✨ Features & Security Modules

The toolkit consists of 9 core security modules organized under the `core/` package:

### 🌐 Network Security
- **Multi-threaded Port Scanner** (`core/port_scanner.py`): Fast multi-threaded port scanning with service detection and banner grabbing.
- **Packet Sniffer** (`core/packet_sniffer.py`): Real-time network traffic sniffer supporting BPF filters, packet parsing (Scapy), and live statistics.

### 🛡️ Web & SSL Security
- **HTTP Security Auditor** (`core/http_auditor.py`): Audits security headers (HSTS, CSP, X-Frame-Options, etc.) and assigns an letter grade (A+ to F).
- **Web Vulnerability Scanner** (`core/vuln_scanner.py`): Tests web endpoints for reflection-based SQLi, XSS, Command Injection, and Path Traversal vulnerabilities.
- **SSL/TLS Checker** (`core/ssl_checker.py`): Inspects SSL/TLS certificate validity, expiration dates, chain of trust, and cipher strength.

### 📁 File & Password Security
- **File Integrity Monitor** (`core/file_hash.py`): Generates hash baselines (SHA-256 / SHA-512) for files/directories and detects unauthorized modifications.
- **Password Strength Analyzer** (`core/password_checker.py`): Evaluates password strength, entropy, and vulnerability to common wordlist attacks.

### 🔍 Intelligence & Automation
- **Directory Scanner** (`core/directory_scanner.py`): Brute-forces web application hidden paths and files with configurable wordlists.
- **Log Analyzer** (`core/log_parser.py`): Parses web/system logs to detect threat patterns, brute-force attempts, IP correlations, and 6 distinct threat classes.

---

## 🛠️ Technology Stack

- **Language:** Python 3.8+
- **GUI:** Tkinter (Custom styled dark mode GUI)
- **Networking & Traffic:** Scapy, Socket Programming, Requests
- **Cryptography & Hashing:** Hashlib, Cryptography, SSL
- **Architecture:** MVC (Model-View-Controller) design pattern with a custom Thread Pool manager (`core/threads.py`)

---

## 📂 Project Structure

```text
security_toolkit/
├── main.py                # Main GUI Application Entry Point
├── requirements.txt       # Dependencies
├── test_core.py           # Core Logic Automated Tests
├── test_gui.py            # GUI Integration Tests
├── run.bat                # Windows Launcher
├── run.sh                 # Linux / macOS Launcher
├── build_exe.bat          # Windows PyInstaller Executable Builder
├── README.md              # Project Documentation
└── core/                  # Security Logic Modules
    ├── port_scanner.py
    ├── file_hash.py
    ├── directory_scanner.py
    ├── vuln_scanner.py
    ├── ssl_checker.py
    ├── password_checker.py
    ├── log_parser.py
    ├── packet_sniffer.py
    ├── http_auditor.py
    ├── ethics.py          # Scope & Consent Validation
    ├── report.py          # PDF/HTML/JSON Report Generator
    ├── session.py         # Session State Management
    ├── threads.py         # Thread Pool Manager
    └── utils.py           # Helper Utilities
```

---

## 🚀 Installation & Usage

### 1. Clone the Repository
```bash
git clone https://github.com/abdusalam-faisal/Professional-Security-Automation-Toolkit.git
cd Professional-Security-Automation-Toolkit
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
- **Via Python:**
  ```bash
  python main.py
  ```
- **Windows (Quick Launch):** Double-click `run.bat`
- **Linux / macOS:** `bash run.sh`

### 4. Build Standalone Executable (Windows)
To create a single `.exe` file for Windows:
```bash
build_exe.bat
```
*(The generated EXE file will be saved in the `dist/` directory)*.

---

## 🧪 Testing

Run functional tests across all core security modules:
```bash
python test_core.py
```

---

## ⚖️ Ethical Usage & Compliance

This project incorporates built-in scope verification (`core/ethics.py`):
- All security scans require user confirmation of authorization.
- Unauthorized scanning or target testing without prior consent is strictly prohibited.

---

## 🚀 Future Improvements

- [ ] CVE Vulnerability Database Integration (NVD API)
- [ ] AI-based Anomaly & Threat Detection
- [ ] Cloud Security Baseline Audit (AWS / Azure)
- [ ] SIEM & Syslog Export Integration

---

## 👤 Author

**Abdusalam Faisal**  
*Cybersecurity Student & Security Developer*  
- GitHub: [@abdusalam-faisal](https://github.com/abdusalam-faisal)

---

## 📜 License

Educational Security Project — Free for educational, research, and authorized auditing purposes.
