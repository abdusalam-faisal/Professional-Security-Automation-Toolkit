#!/usr/bin/env python3
"""
Security Automation Toolkit v2.0 - Professional Edition
Unified GUI security assessment platform (9 tools).
Educational project - authorized/private targets only.
"""
import os
import sys
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from core.port_scanner import EnhancedPortScanner
from core.file_hash import EnhancedFileHashChecker
from core.directory_scanner import DirectoryBruteforcer
from core.vuln_scanner import BasicVulnerabilityScanner
from core.ssl_checker import SSLChecker
from core.password_checker import PasswordStrengthChecker
from core.log_parser import AdvancedLogParser
from core.packet_sniffer import ProfessionalPacketSniffer
from core.http_auditor import EnhancedHTTPHeaderAuditor
from core.ethics import EthicalUsageValidator
from core.report import ReportGenerator
from core.session import SessionManager, DEFAULTS

APP_VERSION = "3.0.0"
THEMES = {
    "Light": {
        "primary": "#1a237e", "secondary": "#0d47a1", "accent": "#6a1b9a",
        "bg": "#eef1f6", "panel": "#ffffff", "text": "#1f2937", "muted": "#64748b",
        "border": "#cbd5e1", "title": "#0f172a",
        "success": "#2e7d32", "danger": "#c62828", "warning": "#f57c00", "info": "#0277bd",
        "hover": "#e2e8f0", "console_bg": "#0f172a", "console_fg": "#d4d4d4",
    },
    "Dark": {
        "primary": "#0ea5e9", "secondary": "#0284c7", "accent": "#a855f7",
        "bg": "#0b1220", "panel": "#101a2e", "text": "#e2e8f0", "muted": "#94a3b8",
        "border": "#1e293b", "title": "#f8fafc",
        "success": "#4ade80", "danger": "#f87171", "warning": "#fbbf24", "info": "#38bdf8",
        "hover": "#1e293b", "console_bg": "#050b18", "console_fg": "#d4d4d4",
    },
}
ICONS = {"success": "✅", "error": "❌", "warning": "⚠️", "info": "ℹ️"}
NAV = [
    ("📊 DASHBOARD", [("📊 Overview", "show_dashboard"), ("📊 Statistics", "show_statistics"), ("📋 Reports", "show_reports")]),
    ("🔍 SCANNING TOOLS", [("🔍 Port Scanner", "show_port_scanner"), ("🌐 Directory Scanner", "show_directory_scanner"), ("⚠️ Vulnerability Scanner", "show_vuln_scanner")]),
    ("🔐 SECURITY TOOLS", [("🔐 File Integrity", "show_file_checker"), ("🔑 Password Checker", "show_password_checker"), ("🔐 SSL/TLS Checker", "show_ssl_checker")]),
    ("📡 NETWORK TOOLS", [("📡 Packet Sniffer", "show_packet_sniffer"), ("📝 Log Analyzer", "show_log_parser"), ("🛡️ HTTP Auditor", "show_http_auditor")]),
    ("⚙️ SYSTEM", [("⚙️ Settings", "show_settings"), ("🔄 Refresh All", "refresh_all"), ("🚪 Exit", "quit_app")]),
]


class EnhancedSecurityToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Security Automation Toolkit - Professional Edition")
        self.root.geometry("1480x900")
        try:
            self.root.state("zoomed")
        except Exception:
            pass
        self.theme_name = "Light"
        self.colors = dict(THEMES[self.theme_name])
        self.session = SessionManager()
        self.reports = ReportGenerator()
        self.auth_var = tk.BooleanVar(value=False)
        self.scan_stats = {"ports_scanned": 0, "files_hashed": 0, "packets_captured": 0,
                           "threats_detected": 0, "vuln_scans": 0, "ssl_checks": 0}
        self.stats_cards = {}
        self.last_results = {}
        self.entries = {}
        self.busy = False
        self._init_tools()
        self._load_session_into_ui()
        self._build_ui()
        self.show_dashboard()

    # ------------------------------------------------------------------ tools
    def _init_tools(self):
        self.tools = {
            "port_scanner": EnhancedPortScanner(self.log_output),
            "file_checker": EnhancedFileHashChecker(self.log_output),
            "directory_scanner": DirectoryBruteforcer(self.log_output),
            "vuln_scanner": BasicVulnerabilityScanner(self.log_output),
            "ssl_checker": SSLChecker(self.log_output),
            "password_checker": PasswordStrengthChecker(self.log_output),
            "log_parser": AdvancedLogParser(self.log_output),
            "packet_sniffer": ProfessionalPacketSniffer(self.log_output),
            "http_auditor": EnhancedHTTPHeaderAuditor(self.log_output),
        }

    # ------------------------------------------------------------------ ui core
    def _build_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        self._setup_styles()
        self.main = tk.Frame(self.root, bg=self.colors["bg"])
        self.main.pack(fill=tk.BOTH, expand=True)
        self._setup_header()
        self._setup_workspace()
        self._setup_status_bar()

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=("Segoe UI", 10), background=self.colors["bg"],
                        foreground=self.colors["text"])
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Card.TFrame", background=self.colors["panel"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Card.TLabel", background=self.colors["panel"], foreground=self.colors["text"])
        style.configure("TLabelframe", background=self.colors["bg"], foreground=self.colors["title"])
        style.configure("TLabelframe.Label", background=self.colors["bg"], foreground=self.colors["title"], font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground=self.colors["panel"], foreground=self.colors["text"])
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["hover"], foreground=self.colors["text"], padding=[12, 6], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.colors["primary"])], foreground=[("selected", "#ffffff")])
        style.configure("Accent.TButton", background=self.colors["primary"], foreground="#ffffff",
                        padding=8, font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Accent.TButton", background=[("active", self.colors["secondary"])])
        style.configure("Danger.TButton", background=self.colors["danger"], foreground="#ffffff", padding=8, font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", background=self.colors["panel"], fieldbackground=self.colors["panel"],
                        foreground=self.colors["text"], rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background=self.colors["hover"], foreground=self.colors["title"],
                        font=("Segoe UI", 9, "bold"))
        style.configure("Vertical.TScrollbar", background=self.colors["hover"], troughcolor=self.colors["bg"])
        style.configure("TProgressbar", background=self.colors["success"], troughcolor=self.colors["bg"])

    def _setup_header(self):
        bar = tk.Frame(self.main, bg=self.colors["primary"], height=64)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        left = tk.Frame(bar, bg=self.colors["primary"])
        left.pack(side=tk.LEFT, padx=18)
        tk.Label(left, text="🔒 SECURITY AUTOMATION TOOLKIT", font=("Segoe UI", 16, "bold"),
                 bg=self.colors["primary"], fg="#ffffff").pack(anchor=tk.W)
        tk.Label(left, text="Professional Security Assessment Platform  |  v" + APP_VERSION,
                 font=("Segoe UI", 9), bg=self.colors["primary"], fg="#c7d2fe").pack(anchor=tk.W)
        right = tk.Frame(bar, bg=self.colors["primary"])
        right.pack(side=tk.RIGHT, padx=14)
        for text, cmd in (("💾 Save Log", self.save_log), ("📋 Copy", self.copy_to_clipboard),
                          ("🧹 Clear", self.clear_output), ("🌓 Theme", self.toggle_theme)):
            tk.Button(right, text=text, command=cmd, bg=self.colors["secondary"], fg="white",
                      font=("Segoe UI", 9), relief="flat", padx=12, pady=6, cursor="hand2",
                      activebackground=self.colors["accent"]).pack(side=tk.LEFT, padx=3)

    def _setup_workspace(self):
        paned = ttk.PanedWindow(self.main, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self._setup_nav(paned)
        right = ttk.Frame(paned)
        paned.add(right, weight=4)
        self.content_frame = ttk.Frame(right)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        console = ttk.Frame(self.notebook)
        self.notebook.add(console, text="📝 Console Output")
        self._setup_console(console)
        stats = ttk.Frame(self.notebook)
        self.notebook.add(stats, text="📊 Statistics")
        self._setup_statistics(stats)

    def _setup_nav(self, parent):
        nav = tk.Frame(parent, bg=self.colors["bg"])
        parent.add(nav, weight=1)
        canvas = tk.Canvas(nav, bg=self.colors["bg"], highlightthickness=0, width=230)
        sb = ttk.Scrollbar(nav, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.colors["bg"])
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        for category, items in NAV:
            tk.Label(inner, text=category, font=("Segoe UI", 9, "bold"),
                     bg=self.colors["bg"], fg=self.colors["primary"]).pack(anchor=tk.W, padx=10, pady=(14, 2))
            for label, method in items:
                btn = tk.Button(inner, text="  " + label, command=lambda m=method: self._nav(m),
                                bg=self.colors["bg"], fg=self.colors["text"], font=("Segoe UI", 9, "bold"),
                                relief="flat", anchor=tk.W, padx=12, pady=7, cursor="hand2",
                                activebackground=self.colors["primary"], activeforeground="white")
                btn.pack(fill=tk.X, padx=6, pady=1)
        tk.Label(inner, text="STATUS", font=("Segoe UI", 9, "bold"),
                 bg=self.colors["bg"], fg=self.colors["primary"]).pack(anchor=tk.W, padx=10, pady=(18, 2))
        for name, status in (("Python", sys.version.split()[0]), ("Requests", "✓"),
                             ("Scapy", "✓" if self.tools["packet_sniffer"].available else "✗"),
                             ("Private targets", "Always allowed")):
            tk.Label(inner, text=f"• {name}: {status}", font=("Segoe UI", 8),
                     bg=self.colors["bg"], fg=self.colors["muted"]).pack(anchor=tk.W, padx=14, pady=1)

    def _nav(self, method):
        getattr(self, method)()

    def _setup_console(self, parent):
        wrap = tk.Frame(parent, bg=self.colors["bg"])
        wrap.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.output_text = tk.Text(wrap, wrap=tk.WORD, font=("Consolas", 10), bg=self.colors["console_bg"],
                                   fg=self.colors["console_fg"], insertbackground="white", state=tk.NORMAL)
        vs = ttk.Scrollbar(wrap, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=vs.set)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        for tag, color in (("info", self.colors["console_fg"]), ("success", "#4ade80"),
                           ("error", "#f87171"), ("warning", "#fbbf24"), ("title", "#60a5fa")):
            self.output_text.tag_config(tag, foreground=color)
        self.output_text.tag_config("title", font=("Consolas", 10, "bold"))
        bar = tk.Frame(parent, bg=self.colors["bg"])
        bar.pack(fill=tk.X, padx=6, pady=(0, 6))
        for text, cmd in (("🧹 Clear", self.clear_output), ("💾 Save", self.save_log),
                          ("📋 Copy All", self.copy_to_clipboard), ("🔍 Search", self.search_console),
                          ("↔️ Wrap", self.toggle_wrap)):
            tk.Button(bar, text=text, command=cmd, bg=self.colors["hover"], fg=self.colors["text"],
                      font=("Segoe UI", 9), relief="flat", padx=10, cursor="hand2").pack(side=tk.LEFT, padx=2)

    def _setup_statistics(self, parent):
        holder = tk.Frame(parent, bg=self.colors["bg"])
        holder.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas = tk.Canvas(holder, bg=self.colors["bg"], highlightthickness=0)
        sb = ttk.Scrollbar(holder, orient=tk.VERTICAL, command=canvas.yview)
        body = tk.Frame(canvas, bg=self.colors["bg"])
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tk.Label(body, text="📊 SECURITY STATISTICS", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["bg"], fg=self.colors["title"]).pack(pady=14)
        cards = [
            ("🔍 Ports Scanned", "ports_scanned", self.colors["info"]),
            ("🔐 Files Hashed", "files_hashed", self.colors["success"]),
            ("📡 Packets Captured", "packets_captured", self.colors["accent"]),
            ("⚠️ Threats Detected", "threats_detected", self.colors["danger"]),
            ("🛡️ Vuln Scans", "vuln_scans", self.colors["warning"]),
            ("🔐 SSL Checks", "ssl_checks", self.colors["secondary"]),
        ]
        rowf = None
        for i, (label, key, color) in enumerate(cards):
            if i % 3 == 0:
                rowf = tk.Frame(body, bg=self.colors["bg"])
                rowf.pack(fill=tk.X, pady=6)
            card = tk.Frame(rowf, bg=self.colors["panel"], relief=tk.RIDGE, bd=1,
                            highlightbackground=self.colors["border"], highlightthickness=1)
            card.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
            tk.Label(card, text=label, font=("Segoe UI", 10, "bold"), bg=self.colors["panel"],
                     fg=color).pack(pady=(14, 2))
            val = tk.Label(card, text="0", font=("Segoe UI", 22, "bold"), bg=self.colors["panel"],
                           fg=self.colors["title"])
            val.pack(pady=(0, 14))
            self.stats_cards[key] = val
        tk.Label(body, text="📅 RECENT ACTIVITY", font=("Segoe UI", 12, "bold"),
                 bg=self.colors["bg"], fg=self.colors["title"]).pack(anchor=tk.W, pady=(18, 4))
        self.activity_list = tk.Text(body, height=7, font=("Segoe UI", 9), bg=self.colors["panel"],
                                     fg=self.colors["muted"], relief=tk.FLAT)
        self.activity_list.pack(fill=tk.X, padx=5)
        self.activity_list.insert(tk.END, "No recent activity.\n")
        self.activity_list.config(state=tk.DISABLED)

    def _setup_status_bar(self):
        bar = tk.Frame(self.main, bg=self.colors["primary"], height=28)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self.status_label = tk.Label(bar, text="✅ System Ready", font=("Segoe UI", 9),
                                     bg=self.colors["primary"], fg="white")
        self.status_label.pack(side=tk.LEFT, padx=12)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=180)
        self.clock = tk.Label(bar, text="", font=("Segoe UI", 9, "bold"),
                              bg=self.colors["primary"], fg="white")
        self.clock.pack(side=tk.RIGHT, padx=12)
        self._tick()

    def _tick(self):
        self.clock.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self._tick)

    # --------------------------------------------------------------- logging
    def log_output(self, message, level="info", immediate=False):
        def _do():
            ts = datetime.now().strftime("%H:%M:%S")
            self.output_text.insert(tk.END, f"[{ts}] {ICONS.get(level, '📝')} {message}\n", level)
            self.output_text.see(tk.END)
            try:
                self.activity_list.config(state=tk.NORMAL)
                if self.activity_list.get(1.0, tk.END).strip() == "No recent activity.":
                    self.activity_list.delete(1.0, tk.END)
                self.activity_list.insert(tk.END, f"[{ts}] {str(message)[:60]}\n")
                self.activity_list.see(tk.END)
                self.activity_list.config(state=tk.DISABLED)
            except Exception:
                pass
            self.status_label.config(text=f"{ICONS.get(level, '')} {str(message)[:50]}")
        if immediate or not getattr(self.root, "after", None):
            _do()
        else:
            self.root.after(0, _do)

    def run_async(self, fn):
        if self.busy:
            self.log_output("Another operation is still running - wait for it to finish.", "warning")
            return False
        self.busy = True
        self.progress.pack(side=tk.LEFT, padx=8, after=self.status_label)
        self.progress.start(12)

        def runner():
            try:
                fn()
            except Exception as exc:
                self.log_output(f"Operation failed: {exc}", "error")
            finally:
                self.root.after(0, self._stop_progress)
        threading.Thread(target=runner, daemon=True).start()
        return True

    def _stop_progress(self):
        self.busy = False
        self.progress.stop()
        self.progress.pack_forget()
        self.status_label.config(text="✅ Ready")

    def update_statistics(self, key, inc=1):
        self.scan_stats[key] = self.scan_stats.get(key, 0) + inc
        if key in self.stats_cards:
            self.stats_cards[key].config(text=str(self.scan_stats[key]))

    # ------------------------------------------------------------ ui helpers
    def clear_content(self):
        for w in self.content_frame.winfo_children():
            w.destroy()

    def _scrollable(self, parent=None):
        parent = parent or self.content_frame
        canvas = tk.Canvas(parent, bg=self.colors["bg"], highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        body = tk.Frame(canvas, bg=self.colors["bg"])
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        return body

    def _page_title(self, body, text, sub=None):
        tk.Label(body, text=text, font=("Segoe UI", 17, "bold"), bg=self.colors["bg"],
                 fg=self.colors["title"]).pack(anchor=tk.W, pady=(6, 2))
        if sub:
            tk.Label(body, text=sub, font=("Segoe UI", 9), bg=self.colors["bg"],
                     fg=self.colors["muted"]).pack(anchor=tk.W, pady=(0, 10))

    def _card(self, body, title):
        frame = tk.LabelFrame(body, text=title, font=("Segoe UI", 10, "bold"),
                              bg=self.colors["bg"], fg=self.colors["title"], padx=14, pady=12,
                              relief=tk.GROOVE, highlightbackground=self.colors["border"])
        frame.pack(fill=tk.X, pady=6)
        return frame

    def _row(self, parent, label, key, default="", width=48, show=None):
        tk.Label(parent, text=label, font=("Segoe UI", 10), bg=self.colors["bg"],
                 fg=self.colors["text"]).grid(row=parent.grid_size()[1], column=0, sticky=tk.W, pady=4, padx=(0, 10))
        ent = tk.Entry(parent, width=width, font=("Segoe UI", 10), show=show,
                       bg=self.colors["panel"], fg=self.colors["text"], relief=tk.SOLID, bd=1,
                       highlightbackground=self.colors["border"])
        ent.insert(0, str(default))
        ent.grid(row=parent.grid_size()[1] - 1, column=1, sticky=tk.W + tk.E, pady=4)
        self.entries[key] = ent
        parent.columnconfigure(1, weight=1)
        return ent

    def _button(self, parent, text, cmd, kind="Accent"):
        return ttk.Button(parent, text=text, command=cmd, style=kind + ".TButton")

    def _info(self, body, text):
        tk.Label(body, text=text, font=("Segoe UI", 9), bg=self.colors["bg"],
                 fg=self.colors["muted"], wraplength=820, justify=tk.LEFT).pack(anchor=tk.W, pady=2)

    def browse_open(self, key, title="Select file"):
        path = filedialog.askopenfilename(title=title)
        if path and key in self.entries:
            self.entries[key].delete(0, tk.END)
            self.entries[key].insert(0, path)

    def browse_dir(self, key, title="Select directory"):
        path = filedialog.askdirectory(title=title)
        if path and key in self.entries:
            self.entries[key].delete(0, tk.END)
            self.entries[key].insert(0, path)

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.log_output("Console cleared.", "info")

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            initialfile="security_toolkit_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_text.get(1.0, tk.END))
            self.log_output(f"Log saved: {path}", "success")

    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))
        self.log_output("Console copied to clipboard.", "success")

    def search_console(self):
        term = simpledialog.askstring("Search Console", "Search term:")
        if not term:
            return
        self.output_text.tag_remove("search", 1.0, tk.END)
        pos = "1.0"
        hits = 0
        while True:
            pos = self.output_text.search(term, pos, tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(term)}c"
            self.output_text.tag_add("search", pos, end)
            self.output_text.tag_config("search", background="#fde047", foreground="black")
            pos = end
            hits += 1
        self.log_output(f"Search: {hits} hit(s) for '{term}'.", "info")

    def toggle_wrap(self):
        self.output_text.config(wrap=tk.WORD if self.output_text.cget("wrap") == tk.NONE else tk.NONE)

    def refresh_all(self):
        self.log_output("Views refreshed.", "success")

    def quit_app(self):
        self.root.destroy()

    # -------------------------------------------------------------- session
    def _load_session_into_ui(self):
        data = self.session.load()
        self.theme_name = data.get("theme", "Light")
        self.auth_var.set(bool(data.get("authorize_public", False)))
        self.session_data = data

    def save_session_state(self):
        data = dict(self.session_data or {})
        for key, ent in self.entries.items():
            if hasattr(ent, "get"):
                try:
                    data[key] = ent.get()
                except Exception:
                    pass
        data["theme"] = self.theme_name
        data["authorize_public"] = bool(self.auth_var.get())
        path = self.session.save(data)
        self.log_output(f"Session saved: {path}", "success")

    def toggle_theme(self):
        self.theme_name = "Dark" if self.theme_name == "Light" else "Light"
        self.colors = dict(THEMES[self.theme_name])
        self._build_ui()
        self.show_dashboard()
        self.log_output(f"Theme switched to {self.theme_name}.", "success")

    # ============================================================== VIEWS
    def show_dashboard(self):
        self.clear_content()
        body = self._scrollable()
        hero = tk.Frame(body, bg=self.colors["primary"])
        hero.pack(fill=tk.X, pady=(4, 10))
        tk.Label(hero, text="Welcome to Security Automation Toolkit",
                 font=("Segoe UI", 22, "bold"), bg=self.colors["primary"], fg="white").pack(pady=(26, 4))
        tk.Label(hero, text="9 professional security tools in one GUI · ethical use · authorized targets only",
                 font=("Segoe UI", 11), bg=self.colors["primary"], fg="#c7d2fe").pack(pady=(0, 26))
        grid = [
            ("🔍", "Port Scanner", "Multi-threaded TCP scan + banners", "show_port_scanner", self.colors["info"]),
            ("🔐", "File Integrity", "Hash verify + directory baseline", "show_file_checker", self.colors["success"]),
            ("🌐", "Directory Scanner", "Web dir discovery + wordlists", "show_directory_scanner", self.colors["warning"]),
            ("⚠️", "Vuln Scanner", "Reflection-based web tests", "show_vuln_scanner", self.colors["danger"]),
            ("🔐", "SSL/TLS Checker", "Cert, expiry, cipher", "show_ssl_checker", self.colors["secondary"]),
            ("🔑", "Password Checker", "Strength, entropy, feedback", "show_password_checker", self.colors["primary"]),
            ("📝", "Log Analyzer", "Threat patterns + IP correlation", "show_log_parser", self.colors["accent"]),
            ("📡", "Packet Sniffer", "Real-time capture (Scapy)", "show_packet_sniffer", self.colors["info"]),
            ("🛡️", "HTTP Auditor", "Security headers + grade A-F", "show_http_auditor", self.colors["success"]),
        ]
        rowf = None
        for i, (icon, title, desc, method, color) in enumerate(grid):
            if i % 3 == 0:
                rowf = tk.Frame(body, bg=self.colors["bg"])
                rowf.pack(fill=tk.X, pady=6)
            card = tk.Frame(rowf, bg=self.colors["panel"], cursor="hand2", relief=tk.RIDGE, bd=1,
                            highlightbackground=self.colors["border"], highlightthickness=1)
            card.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
            tk.Label(card, text=icon, font=("Segoe UI", 22), bg=self.colors["panel"]).pack(pady=(14, 0))
            tk.Label(card, text=title, font=("Segoe UI", 11, "bold"), bg=self.colors["panel"],
                     fg=color).pack(pady=(2, 0))
            tk.Label(card, text=desc, font=("Segoe UI", 8), bg=self.colors["panel"],
                     fg=self.colors["muted"], wraplength=190, justify=tk.CENTER).pack(pady=(0, 14))
            card.bind("<Button-1>", lambda e, m=method: self._nav(m))

    def show_statistics(self):
        self.notebook.select(1)

    def show_reports(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "📋 Reports & Export", "All tool results can be exported as TXT / CSV / JSON.")
        card = self._card(body, "Export last results")
        tk.Label(card, text="Last result sets:", font=("Segoe UI", 9, "bold"),
                 bg=self.colors["bg"], fg=self.colors["text"]).pack(anchor=tk.W)
        self.report_list = tk.Listbox(card, height=8, bg=self.colors["panel"], fg=self.colors["text"],
                                      relief=tk.SOLID, bd=1, font=("Segoe UI", 9))
        self.report_list.pack(fill=tk.X, pady=6)
        for key in ("ports", "vulns", "http", "ssl", "log", "sniff", "hash", "dirs", "password"):
            if key in self.last_results:
                self.report_list.insert(tk.END, f"{key}: {str(self.last_results[key])[:40]}")
        fmt = tk.StringVar(value="txt")
        tk.Label(card, text="Format:", font=("Segoe UI", 9), bg=self.colors["bg"], fg=self.colors["text"]).pack(anchor=tk.W)
        for f in ("txt", "csv", "json"):
            tk.Radiobutton(card, text=f.upper(), variable=fmt, value=f, bg=self.colors["bg"],
                           fg=self.colors["text"], selectcolor=self.colors["panel"]).pack(anchor=tk.W)
        self._button(card, "💾 Export Selected", lambda: self._export_last_sel(fmt.get())).pack(anchor=tk.W, pady=8)
        self._info(body, "All tools also expose their own 'Export report' button.")

    def _export_last_sel(self, fmt):
        sel = self.report_list.curselection()
        if not sel or not hasattr(self, "last_results"):
            messagebox.showinfo("Info", "No results to export yet.")
            return
        key = self.report_list.get(sel[0]).split(":")[0].strip()
        results = self.last_results.get(key)
        if results is None:
            return
        path = self.reports.save(key, results, fmt)
        self.log_output(f"Report exported: {path}", "success")

    def show_settings(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "⚙️ Settings & Configuration",
                         "Configure tools, set the report folder and persist session state.")
        card = self._card(body, "General")
        self._info(card, "Theme: toggle with the '🌓 Theme' button in the header.")
        self.reports_dir_entry = tk.Entry(card, width=60, font=("Segoe UI", 10),
                                          bg=self.colors["panel"], fg=self.colors["text"], relief=tk.SOLID, bd=1)
        self.reports_dir_entry.insert(0, self.reports.output_dir)
        self.reports_dir_entry.pack(anchor=tk.W, pady=4, fill=tk.X)
        self._button(card, "📁 Change Reports Folder", self._pick_reports_dir).pack(anchor=tk.W, pady=6)
        self._button(card, "💾 Save Configuration", self.save_session_state).pack(anchor=tk.W, pady=4)
        auth = self._card(body, "Ethical Use")
        tk.Checkbutton(auth, text="I am authorised to test the public target(s) I enter",
                       variable=self.auth_var, bg=self.colors["bg"], fg=self.colors["text"],
                       selectcolor=self.colors["panel"], font=("Segoe UI", 10)).pack(anchor=tk.W)
        self._info(auth, "Private/loopback targets are always allowed. Public hosts are blocked unless "
                         "this box is ticked - academic projects only, no exploitation.")

    def _pick_reports_dir(self):
        path = filedialog.askdirectory(title="Reports folder")
        if path:
            self.reports = ReportGenerator(path)
            self.reports_dir_entry.delete(0, tk.END)
            self.reports_dir_entry.insert(0, path)
            self.log_output(f"Reports folder: {path}", "success")

    # ============================================================ PORT SCANNER
    def show_port_scanner(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🔍 Port Scanner",
                         "Multi-threaded TCP connect scan with service detection and banner grabbing.")
        cfg = self._card(body, "Scan Configuration")
        self._row(cfg, "Target host / IP:", "target", self.session_data.get("target", "127.0.0.1"), 30)
        self._row(cfg, "Port range:", "port_range", self.session_data.get("port_range", "1-1024"), 30)
        self._row(cfg, "Threads (10-500):", "threads", self.session_data.get("threads", 100), 10)
        q = tk.Frame(cfg, bg=self.colors["bg"])
        for label, value in (("Common", "1-1000"), ("Standard", "1-1024"), ("Web", "80,443,8080,8443"), ("All", "1-65535")):
            ttk.Button(q, text=label, command=lambda v=value: self._set_entry("port_range", v),
                       style="Accent.TButton").pack(side=tk.LEFT, padx=3, pady=3)
        q.grid(row=cfg.grid_size()[1], column=0, columnspan=2, sticky=tk.W)
        chk = tk.Frame(cfg, bg=self.colors["bg"])
        tk.Checkbutton(chk, text="I am authorised to test this target", variable=self.auth_var,
                       bg=self.colors["bg"], fg=self.colors["text"], selectcolor=self.colors["panel"]).pack(side=tk.LEFT)
        chk.grid(row=cfg.grid_size()[1], column=0, columnspan=2, sticky=tk.W)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🚀 Start Scan", self.start_port_scan).pack(side=tk.LEFT, padx=4)
        self._button(btns, "🧹 Clear Results", self.clear_results, "Danger").pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("ports")).pack(side=tk.LEFT, padx=4)
        res = self._card(body, "Scan Results")
        cols = ("port", "service", "status", "banner")
        self.results_tree = ttk.Treeview(res, columns=cols, show="headings", height=12)
        for c, w in (("port", 90), ("service", 130), ("status", 90), ("banner", 430)):
            self.results_tree.heading(c, text=c.title())
            self.results_tree.column(c, width=w)
        vs = ttk.Scrollbar(res, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=vs.set)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)

    def _set_entry(self, key, value):
        if key in self.entries:
            self.entries[key].delete(0, tk.END)
            self.entries[key].insert(0, value)

    def start_port_scan(self):
        target = self.entries["target"].get().strip()
        port_range = self.entries["port_range"].get().strip()
        if not target or not port_range:
            messagebox.showerror("Error", "Target and port range are required.")
            return
        ok, msg = EthicalUsageValidator(self.log_output).validate(target, self.auth_var.get())
        if not ok:
            self.log_output(msg, "error")
            return
        self.log_output(f"Ethics: {msg}", "success")
        self.clear_results()

        def job():
            try:
                found = self.tools["port_scanner"].threaded_scan(
                    target, port_range, max(10, min(500, int(self.entries["threads"].get() or 100))))
                self.last_results["ports"] = found
                self.root.after(0, lambda: self._fill_ports(found))
            except Exception as exc:
                self.log_output(f"Scan error: {exc}", "error")
        self.run_async(job)

    def _fill_ports(self, found):
        for port, service, banner in sorted(found):
            self.results_tree.insert("", tk.END, values=(port, service, "Open", (banner or "")[:120]))
        self.update_statistics("ports_scanned", len(found))
        self.log_output(f"Port scan finished - {len(found)} open ports.", "success")

    def clear_results(self):
        if hasattr(self, "results_tree"):
            self.results_tree.delete(*self.results_tree.get_children())

    def _export_current(self, key):
        if key not in self.last_results or not self.last_results[key]:
            messagebox.showinfo("Info", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile=f"{key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for row in self.last_results[key]:
                    f.write(str(row) + "\n")
            self.log_output(f"Exported: {path}", "success")

    # ========================================================== FILE CHECKER
    def show_file_checker(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🔐 File Integrity Checker",
                         "Calculate hashes (MD5/SHA-1/SHA-256/SHA-512/SHA3-256), verify integrity, "
                         "create directory baselines and audit changes.")
        nb = ttk.Notebook(body)
        nb.pack(fill=tk.X)
        t1 = ttk.Frame(nb)
        nb.add(t1, text="📄 Single File")
        self._row(t1, "File:", "hash_file", self.session_data.get("hash_file", ""), 46)
        ttk.Button(t1, text="📁 Browse", command=lambda: self.browse_open("hash_file"),
                   style="Accent.TButton").grid(row=0, column=2, padx=6)
        tk.Label(t1, text="Algorithm:", font=("Segoe UI", 10), bg=self.colors["bg"],
                 fg=self.colors["text"]).grid(row=1, column=0, sticky=tk.W, pady=4)
        self.hash_algo = ttk.Combobox(t1, values=["md5", "sha1", "sha256", "sha512", "sha3_256"],
                                      state="readonly", width=16)
        self.hash_algo.set("sha256")
        self.hash_algo.grid(row=1, column=1, sticky=tk.W, pady=4)
        tk.Label(t1, text="Expected hash (to verify):", font=("Segoe UI", 10), bg=self.colors["bg"],
                 fg=self.colors["text"]).grid(row=2, column=0, sticky=tk.W, pady=4)
        self.expected_hash = tk.Entry(t1, width=64, font=("Consolas", 9),
                                      bg=self.colors["panel"], fg=self.colors["text"])
        self.expected_hash.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=4)
        bt = tk.Frame(t1, bg=self.colors["bg"])
        bt.grid(row=3, column=0, columnspan=3, pady=8)
        self._button(bt, "🔍 Calculate Hash", self.calc_single_hash).pack(side=tk.LEFT, padx=4)
        self._button(bt, "✅ Verify Integrity", self.verify_single_hash).pack(side=tk.LEFT, padx=4)
        t2 = ttk.Frame(nb)
        nb.add(t2, text="📁 Directory Baseline")
        self._row(t2, "Directory:", "hash_dir", self.session_data.get("hash_dir", ""), 46)
        ttk.Button(t2, text="📁 Browse", command=lambda: self.browse_dir("hash_dir"),
                   style="Accent.TButton").grid(row=0, column=2, padx=6)
        ttk.Button(t2, text="📊 Create Baseline", command=self.create_baseline,
                   style="Accent.TButton").grid(row=1, column=0, columnspan=3, pady=8, sticky=tk.W)
        self._row(t2, "Baseline JSON:", "baseline_file", "", 46)
        ttk.Button(t2, text="📁 Browse", command=lambda: self.browse_open("baseline_file", "Baseline file"),
                   style="Accent.TButton").grid(row=2, column=2, padx=6)
        ttk.Button(t2, text="🔍 Audit vs Baseline", command=self.audit_baseline,
                   style="Accent.TButton").grid(row=3, column=0, pady=8, sticky=tk.W)

    def calc_single_hash(self):
        path = self.entries["hash_file"].get().strip()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Choose a valid file.")
            return
        algo = self.hash_algo.get()
        def job():
            digest = self.tools["file_checker"].calculate_hash(path, algo)
            if digest:
                self.last_results["hash"] = {"file": path, "algorithm": algo, "hash": digest}
                self.root.after(0, lambda: self.expected_hash.delete(0, tk.END) or self.expected_hash.insert(0, digest))
                self.root.after(0, lambda: self.update_statistics("files_hashed", 1))
        self.run_async(job)

    def verify_single_hash(self):
        path = self.entries["hash_file"].get().strip()
        expected = self.expected_hash.get().strip()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Choose a valid file.")
            return
        self.run_async(lambda: self.tools["file_checker"].verify_file(path, expected or None, self.hash_algo.get()))

    def create_baseline(self):
        d = self.entries["hash_dir"].get().strip()
        if not os.path.isdir(d):
            messagebox.showerror("Error", "Choose a valid directory.")
            return
        def job():
            out = self.tools["file_checker"].create_directory_baseline(d, self.hash_algo.get())
            if out:
                self.root.after(0, lambda: self._set_entry("baseline_file", out))
                self.root.after(0, lambda: self.update_statistics("files_hashed", 1))
        self.run_async(job)

    def audit_baseline(self):
        base, d = self.entries["baseline_file"].get().strip(), self.entries["hash_dir"].get().strip()
        if not os.path.isfile(base):
            messagebox.showerror("Error", "Choose a baseline JSON file.")
            return
        def job():
            audit = self.tools["file_checker"].compare_baseline(base, d or None)
            if audit:
                self.last_results["hash"] = audit
                self.log_output(f"Audit: {audit['unchanged']} unchanged, {len(audit['changed'])} modified, "
                                f"{len(audit['new'])} new, {len(audit['deleted'])} deleted.", "info")
        self.run_async(job)

    # =========================================================== DIR SCANNER
    def show_directory_scanner(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🌐 Directory Scanner",
                         "Web directory enumeration with built-in wordlist or your own custom wordlist.")
        cfg = self._card(body, "Scanner Configuration")
        self._row(cfg, "Base URL:", "dir_url", self.session_data.get("dir_url", "http://localhost"), 40)
        self._row(cfg, "Wordlist file (optional):", "dir_wordlist", self.session_data.get("dir_wordlist", ""), 40)
        ttk.Button(cfg, text="📂 Browse", command=lambda: self.browse_open("dir_wordlist", "Wordlist"),
                   style="Accent.TButton").grid(row=cfg.grid_size()[1] - 1, column=2, padx=6)
        self._row(cfg, "Extensions (e.g. php,txt):", "dir_ext", "", 40)
        self._row(cfg, "Threads:", "dir_threads", 20, 10)
        chk = tk.Frame(cfg, bg=self.colors["bg"])
        tk.Checkbutton(chk, text="I am authorised to test this target", variable=self.auth_var,
                       bg=self.colors["bg"], fg=self.colors["text"], selectcolor=self.colors["panel"]).pack(side=tk.LEFT)
        chk.grid(row=cfg.grid_size()[1], column=0, columnspan=2, sticky=tk.W)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🚀 Start Scan", self.start_directory_scan).pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("dirs")).pack(side=tk.LEFT, padx=4)

    def start_directory_scan(self):
        url = self.entries["dir_url"].get().strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        ok, msg = EthicalUsageValidator(self.log_output).validate(url, self.auth_var.get())
        if not ok:
            self.log_output(msg, "error")
            return
        self.log_output(f"Ethics: {msg}", "success")
        wl = self.entries.get("dir_wordlist", self.entries["dir_url"])
        wordlist = wl.get().strip() if hasattr(wl, "get") else ""
        ext = [e.strip() for e in self.entries["dir_ext"].get().split(",") if e.strip()]

        def job():
            found = self.tools["directory_scanner"].brute_force(
                url, wordlist, extensions=ext,
                max_threads=max(1, min(100, int(self.entries["dir_threads"].get() or 20))))
            self.last_results["dirs"] = found
        self.run_async(job)

    # ============================================================ VULN SCANNER
    def show_vuln_scanner(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "⚠️ Vulnerability Scanner",
                         "Reflection-based tests for SQL injection, XSS, path traversal and command injection. "
                         "Passive detection only - no exploitation.")
        cfg = self._card(body, "Target Configuration")
        self._row(cfg, "Target URL:", "vuln_url", self.session_data.get("vuln_url", "http://localhost"), 44)
        chk = tk.Frame(cfg, bg=self.colors["bg"])
        tk.Checkbutton(chk, text="I am authorised to test this target", variable=self.auth_var,
                       bg=self.colors["bg"], fg=self.colors["text"], selectcolor=self.colors["panel"]).pack(side=tk.LEFT)
        chk.grid(row=cfg.grid_size()[1], column=0, columnspan=2, sticky=tk.W)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🚀 Start Scan", self.start_vuln_scan, "Danger").pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("vulns")).pack(side=tk.LEFT, padx=4)

    def start_vuln_scan(self):
        url = self.entries["vuln_url"].get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a URL.")
            return
        def job():
            res = self.tools["vuln_scanner"].scan_url(url, authorized=self.auth_var.get())
            self.last_results["vulns"] = res
            if res:
                self.root.after(0, lambda: self.update_statistics("vuln_scans", 1))
        self.run_async(job)

    # ============================================================= SSL CHECKER
    def show_ssl_checker(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🔐 SSL/TLS Checker",
                         "Validates the certificate chain and reports issuer, expiry, cipher and protocol.")
        cfg = self._card(body, "Target Configuration")
        self._row(cfg, "Hostname:", "ssl_host", self.session_data.get("ssl_host", "google.com"), 30)
        self._row(cfg, "Port:", "ssl_port", self.session_data.get("ssl_port", "443"), 10)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🔍 Check SSL", self.start_ssl_check).pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("ssl")).pack(side=tk.LEFT, padx=4)

    def start_ssl_check(self):
        host = self.entries["ssl_host"].get().strip()
        port = self.entries["ssl_port"].get().strip()
        if not host or not port.isdigit():
            messagebox.showerror("Error", "Enter a valid hostname and port.")
            return
        def job():
            res = self.tools["ssl_checker"].check_ssl(host, int(port))
            self.last_results["ssl"] = res
            self.root.after(0, lambda: self.update_statistics("ssl_checks", 1))
        self.run_async(job)

    # ========================================================= PASSWORD CHECKER
    def show_password_checker(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🔑 Password Strength Checker",
                         "Scores length, variety and commonality; computes entropy in bits.")
        cfg = self._card(body, "Password Analysis")
        self._row(cfg, "Enter password:", "password_input", "", 30, show="•")
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🔍 Analyze", self.start_password_check).pack(side=tk.LEFT, padx=4)

    def start_password_check(self):
        pwd = self.entries["password_input"].get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        res = self.tools["password_checker"].check_password(pwd)
        self.last_results["password"] = res
        self.entries["password_input"].delete(0, tk.END)

    # ============================================================ LOG ANALYZER
    def show_log_parser(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "📝 Log Analyzer",
                         "Pattern-based threat detection (SQLi, XSS, traversal, CMDi, brute-force, enumeration) "
                         "with IP correlation, top attackers and threat level. Works on files or pasted text.")
        nb = ttk.Notebook(body)
        nb.pack(fill=tk.X)
        t1 = ttk.Frame(nb)
        nb.add(t1, text="📄 From File")
        self._row(t1, "Log file:", "log_file", self.session_data.get("log_file", ""), 46)
        ttk.Button(t1, text="📁 Browse", command=lambda: self.browse_open("log_file", "Log file"),
                   style="Accent.TButton").grid(row=0, column=2, padx=6)
        ttk.Button(t1, text="🔍 Analyze File", command=self.start_log_analysis,
                   style="Danger.TButton").grid(row=1, column=0, pady=8, sticky=tk.W)
        t2 = ttk.Frame(nb)
        nb.add(t2, text="📋 Paste Text")
        self.log_text_widget = tk.Text(t2, height=10, font=("Consolas", 9),
                                       bg=self.colors["panel"], fg=self.colors["text"])
        self.log_text_widget.pack(fill=tk.X, pady=4)
        self._button(t2, "🔍 Analyze Pasted Log", self.analyze_pasted_log, "Danger").pack(anchor=tk.W, pady=4)

    def start_log_analysis(self):
        path = self.entries["log_file"].get().strip()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Choose a valid log file.")
            return
        def job():
            findings = self.tools["log_parser"].analyze_file(path)
            self.tools["log_parser"].report(findings)
            self.last_results["log"] = findings
            if findings:
                self.root.after(0, lambda: self.update_statistics(
                    "threats_detected", findings["summary"]["suspicious_activity"]))
        self.run_async(job)

    def analyze_pasted_log(self):
        text = self.log_text_widget.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Paste some log text first.")
            return
        def job():
            findings = self.tools["log_parser"].analyze(text, "pasted text")
            self.tools["log_parser"].report(findings)
            self.last_results["log"] = findings
            if findings:
                self.root.after(0, lambda: self.update_statistics(
                    "threats_detected", findings["summary"]["suspicious_activity"]))
        self.run_async(job)

    # =========================================================== PACKET SNIFFER
    def show_packet_sniffer(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "📡 Packet Sniffer",
                         "Real-time capture and protocol dissection via Scapy. Needs admin/root privileges "
                         "and the scapy package. Use BPF filters to narrow capture.")
        cfg = self._card(body, "Sniffer Configuration")
        self._row(cfg, "Packet count:", "sniff_count", self.session_data.get("sniff_count", 50), 10)
        self._row(cfg, "Timeout (s):", "sniff_timeout", self.session_data.get("sniff_timeout", 30), 10)
        self._row(cfg, "BPF filter (optional):", "sniff_filter", self.session_data.get("sniff_filter", ""), 30)
        self._row(cfg, "Interface (blank = default):", "sniff_interface", self.session_data.get("sniff_interface", ""), 30)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "📡 Start Capture", self.start_packet_sniff).pack(side=tk.LEFT, padx=4)
        self._button(btns, "🛑 Stop", self.stop_sniff).pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("sniff")).pack(side=tk.LEFT, padx=4)

    def start_packet_sniff(self):
        count = self.entries["sniff_count"].get().strip()
        timeout = self.entries["sniff_timeout"].get().strip()
        if not count.isdigit() or not timeout.isdigit():
            messagebox.showerror("Error", "Count and timeout must be integers.")
            return
        if not self.tools["packet_sniffer"].available:
            self.log_output("Scapy not installed or no root/admin privileges - capture will fail.",
                            "warning")
        def job():
            pkts = self.tools["packet_sniffer"].start_sniffing(
                int(count), int(timeout),
                filter_exp=self.entries["sniff_filter"].get().strip(),
                interface=self.entries["sniff_interface"].get().strip() or None)
            self.last_results["sniff"] = self.tools["packet_sniffer"].captured
            self.root.after(0, lambda: self.update_statistics("packets_captured", len(pkts)))
        self.run_async(job)

    def stop_sniff(self):
        self.tools["packet_sniffer"].stop_sniffing()

    # ============================================================ HTTP AUDITOR
    def show_http_auditor(self):
        self.clear_content()
        body = self._scrollable()
        self._page_title(body, "🛡️ HTTP Security Header Auditor",
                         "Grades 8 security headers (HSTS, CSP, X-Frame-Options, ...) plus HTTPS and cookie "
                         "checks, and gives an A-F letter grade.")
        cfg = self._card(body, "Target URL")
        self._row(cfg, "URL to audit:", "http_url", self.session_data.get("http_url", "https://example.com"), 44)
        chk = tk.Frame(cfg, bg=self.colors["bg"])
        tk.Checkbutton(chk, text="I am authorised to test this target", variable=self.auth_var,
                       bg=self.colors["bg"], fg=self.colors["text"], selectcolor=self.colors["panel"]).pack(side=tk.LEFT)
        chk.grid(row=cfg.grid_size()[1], column=0, columnspan=2, sticky=tk.W)
        btns = tk.Frame(body, bg=self.colors["bg"])
        btns.pack(fill=tk.X, pady=8)
        self._button(btns, "🛡️ Audit Headers", self.start_http_audit).pack(side=tk.LEFT, padx=4)
        self._button(btns, "💾 Export Report", lambda: self._export_current("http")).pack(side=tk.LEFT, padx=4)

    def start_http_audit(self):
        url = self.entries["http_url"].get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a URL.")
            return
        def job():
            res = self.tools["http_auditor"].audit_url(url, authorized=self.auth_var.get())
            self.last_results["http"] = res
        self.run_async(job)



def main():
    root = tk.Tk()
    EnhancedSecurityToolkitGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
