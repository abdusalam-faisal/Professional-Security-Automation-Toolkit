"""Pattern-based threat detection over web/server log files or pasted text."""
import re
from datetime import datetime

from . import utils

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

THREAT_PATTERNS = {
    "sql_injection": {
        "patterns": [r"union\s+select", r"select.*\s+from", r"insert\s+into",
                     r"delete\s+from", r"update\s+.*\s+set", r"or\s+1\s*=\s*1", r"or\s*['\"]\s*1\s*['\"]\s*=\s*['\"]\s*1",
                     r"exec\s*\(", r"xp_cmdshell", r"--\s"],
        "severity": "critical", "description": "SQL injection attempt"},
    "xss": {
        "patterns": [r"<script.*?>", r"javascript:", r"alert\s*\(", r"onerror=",
                     r"onload=", r"<iframe", r"document\.cookie", r"eval\s*\("],
        "severity": "high", "description": "Cross-site scripting attempt"},
    "path_traversal": {
        "patterns": [r"\.\./", r"\.\.\\", r"\..\..%2f", r"%2e%2e", r"/etc/passwd", r"C:\\Windows\\",
                     r"/proc/self/", r"/bin/(ba)?sh"],
        "severity": "high", "description": "Path traversal attempt"},
    "command_injection": {
        "patterns": [r";\s*ls", r"`.*`", r"\|\|", r"&&\s*(whoami|id|cat)",
                     r"\$\(.*\)", r"\|\s*sh", r"wget\s+http", r"curl\s+http"],
        "severity": "critical", "description": "Command injection attempt"},
    "brute_force": {
        "patterns": [r"failed password", r"invalid password", r"authentication failure",
                     r"login failed", r"access denied", r"invalid user"],
        "severity": "medium", "description": "Brute force attempt"},
    "directory_enumeration": {
        "patterns": [r"\.git/", r"\.env", r"wp-config\.php", r"\.DS_Store",
                     r"\.bak\b", r"\.old\b", r"\.sql\b", r"\.tar\.gz\b"],
        "severity": "low", "description": "Directory/file enumeration"},
}

TIMESTAMP_RES = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]


class AdvancedLogParser:
    """Streams log content line by line; pre-compiled regexes, IP correlation,
    per-attack statistics, top attackers and a threat level."""

    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.compiled = {
            name: [re.compile(p, re.IGNORECASE) for p in info["patterns"]]
            for name, info in THREAT_PATTERNS.items()}

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    @staticmethod
    def _timestamp(line):
        for rx in TIMESTAMP_RES:
            m = rx.search(line)
            if m:
                return m.group(1)
        return None

    def analyze(self, log_text, source="pasted text"):
        lines = log_text.splitlines() if isinstance(log_text, str) else list(log_text)
        self.log(f"Analyzing log source: {source} ({len(lines)} lines)", "info")
        summary = {"source": source, "total_lines": len(lines), "suspicious_activity": 0,
                   "unique_ips": set(), "attacks_by_type": {}}
        details, ip_counter = [], {}
        for num, line in enumerate(lines, 1):
            ip = IP_RE.search(line)
            source_ip = ip.group(0) if ip else "Unknown"
            if source_ip != "Unknown":
                ip_counter[source_ip] = ip_counter.get(source_ip, 0) + 1
                summary["unique_ips"].add(source_ip)
            for attack_type, regexes in self.compiled.items():
                for pattern in regexes:
                    if pattern.search(line):
                        details.append({"line": num, "attack_type": attack_type,
                                        "description": THREAT_PATTERNS[attack_type]["description"],
                                        "severity": THREAT_PATTERNS[attack_type]["severity"],
                                        "source_ip": source_ip, "timestamp": self._timestamp(line),
                                        "raw": line.strip()[:200]})
                        summary["suspicious_activity"] += 1
                        summary["attacks_by_type"][attack_type] = summary["attacks_by_type"].get(attack_type, 0) + 1
                        break
        top = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        return {"summary": summary, "details": details, "top_attackers": dict(top)}

    def analyze_file(self, log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                return self.analyze(f.read(), source=log_file)
        except FileNotFoundError:
            self.log(f"Log file not found: {log_file}", "error")
            return {}
        except PermissionError:
            self.log(f"Permission denied: {log_file}", "error")
            return {}

    def report(self, findings):
        if not findings:
            return
        s = findings["summary"]
        self.log("\nLOG ANALYSIS SUMMARY", "info")
        self.log("=" * 60, "info")
        self.log(f"Total log entries: {s['total_lines']:,}", "info")
        self.log(f"Unique IP addresses: {len(s['unique_ips']):,}", "info")
        self.log(f"Suspicious activities: {s['suspicious_activity']:,}", "info")
        if s["attacks_by_type"]:
            self.log("\nTHREAT BREAKDOWN:", "info")
            for atype, count in sorted(s["attacks_by_type"].items(), key=lambda x: -x[1]):
                sev = THREAT_PATTERNS[atype]["severity"]
                icon = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MED]", "low": "[LOW]"}[sev]
                self.log(f"  {icon} {atype}: {count} incidents", "warning" if sev in ("high", "critical") else "info")
        if findings["top_attackers"]:
            self.log("\nTOP ATTACKERS:", "info")
            for ip, count in list(findings["top_attackers"].items())[:5]:
                self.log(f"  {ip}: {count} events", "warning")
        suspicious, ips = s["suspicious_activity"], len(s["unique_ips"])
        if suspicious > 100 or ips > 50:
            level = "CRITICAL"
        elif suspicious > 50 or ips > 20:
            level = "HIGH"
        elif suspicious > 10 or ips > 5:
            level = "MEDIUM"
        elif suspicious > 0:
            level = "LOW"
        else:
            level = "CLEAN"
        color = "error" if level in ("CRITICAL", "HIGH") else "warning" if level in ("MEDIUM", "LOW") else "success"
        self.log(f"\nTHREAT LEVEL: {level}", color)
