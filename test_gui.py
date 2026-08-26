"""GUI smoke test: builds every view under a virtual display and screenshots."""
import os
import subprocess
import sys
import time
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import EnhancedSecurityToolkitGUI, APP_VERSION

VIEWS = [
    "show_dashboard", "show_port_scanner", "show_file_checker", "show_directory_scanner",
    "show_vuln_scanner", "show_ssl_checker", "show_password_checker", "show_log_parser",
    "show_packet_sniffer", "show_http_auditor", "show_reports", "show_settings",
]


def main():
    root = tk.Tk()
    app = EnhancedSecurityToolkitGUI(root)
    root.update()
    for view in VIEWS:
        getattr(app, view)()
        root.update()
        print(f"[GUI] view ok: {view}")
    time.sleep(1)
    root.update()
    try:
        subprocess.run(["import", "-window", "root", "/home/user/proj/shot_dashboard.png"],
                       check=True, timeout=20)
        print("[GUI] screenshot saved")
    except Exception as exc:
        print("[GUI] screenshot failed:", exc)
    app.show_port_scanner()
    root.update()
    time.sleep(0.4)
    try:
        subprocess.run(["import", "-window", "root", "/home/user/proj/shot_portscanner.png"],
                       check=True, timeout=20)
        print("[GUI] screenshot 2 saved")
    except Exception as exc:
        print("[GUI] screenshot 2 failed:", exc)
    root.destroy()
    print("GUI SMOKE OK -", APP_VERSION)


if __name__ == "__main__":
    main()
