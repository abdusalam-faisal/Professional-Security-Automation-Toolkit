"""Web server security header audit with grading (A-F) and extra checks."""
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

from .ethics import EthicalUsageValidator

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "critical", "description": "Enforces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains",
        "verify": lambda v: "max-age=" in v and v.split("max-age=")[1].split(";")[0].strip().isdigit() and int(v.split("max-age=")[1].split(";")[0]) >= 31536000},
    "Content-Security-Policy": {
        "severity": "critical", "description": "Prevents XSS attacks",
        "recommended": "default-src 'self'",
        "verify": lambda v: len(v) > 10},
    "X-Frame-Options": {
        "severity": "high", "description": "Prevents clickjacking",
        "recommended": "DENY or SAMEORIGIN",
        "verify": lambda v: v.upper() in ("DENY", "SAMEORIGIN")},
    "X-Content-Type-Options": {
        "severity": "medium", "description": "Prevents MIME sniffing",
        "recommended": "nosniff",
        "verify": lambda v: "nosniff" in v.lower()},
    "X-XSS-Protection": {
        "severity": "medium", "description": "Enables XSS filtering",
        "recommended": "1; mode=block",
        "verify": lambda v: "1; mode=block" in v.lower()},
    "Referrer-Policy": {
        "severity": "low", "description": "Controls referrer information",
        "recommended": "strict-origin-when-cross-origin",
        "verify": lambda v: "strict" in v.lower() or "origin" in v.lower()},
    "Permissions-Policy": {
        "severity": "medium", "description": "Controls browser features",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "verify": lambda v: len(v) > 5},
    "Cache-Control": {
        "severity": "low", "description": "Controls caching behavior",
        "recommended": "no-store for sensitive data",
        "verify": lambda v: any(k in v.lower() for k in ("no-store", "no-cache", "private"))},
}


class EnhancedHTTPHeaderAuditor:
    """Sends one GET, grades the security headers, checks HTTPS and cookies."""

    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.ethics = EthicalUsageValidator(output_callback)

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def audit_url(self, url, authorized=False):
        if not REQUESTS_OK:
            self.log("Requests library not available - auditor disabled.", "error")
            return {}
        ok, msg = self.ethics.validate(url, authorized)
        if not ok:
            self.log(msg, "error")
            return {}
        self.log(msg, "success")
        try:
            r = requests.get(url, timeout=15, allow_redirects=True,
                             headers={"User-Agent": "SecurityToolkit-Auditor/2.0"})
        except Exception as exc:
            self.log(f"Connection error: {exc}", "error")
            return {}
        self.log(f"Final URL: {r.url} | Status: {r.status_code} | "
                 f"Server: {r.headers.get('Server', 'not disclosed')} | "
                 f"Content: {len(r.content):,} B", "info")

        results = {"url": r.url, "status_code": r.status_code,
                   "server": r.headers.get("Server"),
                   "present_headers": [], "weak_headers": [], "missing_headers": [], "grade": "A", "score": 100}
        self.log("\nSECURITY HEADER ANALYSIS:", "info")
        self.log("=" * 60, "info")
        for name, meta in SECURITY_HEADERS.items():
            if name in r.headers:
                value = r.headers[name]
                if meta["verify"](value):
                    results["present_headers"].append({"name": name, "value": value[:80]})
                    self.log(f"[OK] {name}: {value[:60]}...", "success")
                else:
                    results["weak_headers"].append({"name": name, "value": value[:80]})
                    self.log(f"[WEAK] {name}: {value[:60]}... Recommended: {meta['recommended']}", "warning")
            else:
                results["missing_headers"].append({"name": name, "severity": meta["severity"]})
                self.log(f"[MISSING] {name} ({meta['description']})", "error")
                self.log(f"   Recommended: {meta['recommended']}", "info")

        score = 100
        weights = {"critical": 20, "high": 15, "medium": 10, "low": 5}
        for h in results["missing_headers"]:
            score -= weights.get(h["severity"], 5)
        for h in results["weak_headers"]:
            name = h["name"]
            score -= weights.get(SECURITY_HEADERS[name]["severity"], 5) // 2
        results["score"] = max(0, score)
        results["grade"] = ("A" if results["score"] >= 90 else "B" if results["score"] >= 80
                            else "C" if results["score"] >= 70 else "D" if results["score"] >= 60 else "F")
        color = "success" if results["grade"] in ("A", "B") else "warning" if results["grade"] in ("C", "D") else "error"
        self.log("\nSECURITY ASSESSMENT", "info")
        self.log("=" * 60, "info")
        self.log(f"SECURITY GRADE: {results['grade']} | SCORE: {results['score']}/100", color)
        self.log(f"Present: {len(results['present_headers'])} | Weak: {len(results['weak_headers'])} | "
                 f"Missing: {len(results['missing_headers'])}", "info")

        self.log("\nADDITIONAL SECURITY CHECKS:", "info")
        results["https_enabled"] = r.url.startswith("https://")
        self.log(f"HTTPS: {'Enabled' if results['https_enabled'] else 'NOT enabled'}",
                 "success" if results["https_enabled"] else "error")
        if r.cookies:
            insecure = [c.name for c in r.cookies if not c.secure or "httponly" not in str(c._rest).lower()]
            results["insecure_cookies"] = insecure
            self.log(f"Cookies: {len(r.cookies)} set, {len(insecure)} insecure (missing Secure/HttpOnly)", "warning")
        else:
            self.log("Cookies: none set", "info")
        results["response_time_ms"] = round(r.elapsed.total_seconds() * 1000, 1) if hasattr(r, "elapsed") else None
        if results["response_time_ms"] is not None:
            self.log(f"Response time: {results['response_time_ms']} ms", "info")
        return results
