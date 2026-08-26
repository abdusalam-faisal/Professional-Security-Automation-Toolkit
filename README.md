# 🔒 Security Automation Toolkit v3.0 — Professional Edition

Unified GUI security assessment platform (9 tools) built on Tkinter + Scapy.
Academic project — educational use, authorized targets only.

## Quick start
```bash
pip install -r requirements.txt
python main.py
```
Windows: double-click `run.bat` · Linux/macOS: `bash run.sh`
Build an EXE (Windows): `build_exe.bat` → `pyinstaller --onefile --windowed --name SecurityToolkit main.py`

## Tools & requirement mapping
| Tool | File | Key functions |
|---|---|---|
| Port Scanner | core/port_scanner.py | threaded_scan, scan_port, banner grabbing |
| File Integrity | core/file_hash.py | calculate_hash, verify_file, create_directory_baseline, compare_baseline |
| Directory Scanner | core/directory_scanner.py | brute_force (+ custom wordlists) |
| Vulnerability Scanner | core/vuln_scanner.py | scan_url (reflection-based SQLi/XSS/traversal/CMDi) |
| SSL/TLS Checker | core/ssl_checker.py | check_ssl (expiry, cipher, chain) |
| Password Checker | core/password_checker.py | check_password (score + entropy) |
| Log Analyzer | core/log_parser.py | analyze / analyze_file / report (6 threat classes) |
| Packet Sniffer | core/packet_sniffer.py | start_sniffing (BPF filter, live stats) |
| HTTP Auditor | core/http_auditor.py | audit_url (8 headers, grade A–F) |

## Architecture
- `core/` — logic layer (thread pool, ethics validator, report generator, session manager)
- `main.py` — GUI layer (MVC style separation)
- `run.sh` / `run.bat` / `build_exe.bat` — launchers
- `test_core.py` — functional tests (all tools)
