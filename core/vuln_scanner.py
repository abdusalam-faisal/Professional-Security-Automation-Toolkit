"""Passive/reflective web vulnerability scanner (SQLi, XSS, traversal, CMDi)."""
import re
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

from .ethics import EthicalUsageValidator


class BasicVulnerabilityScanner:
    """Sends benign reflection payloads; flags when the payload echoes back.

    Detection is *reflection-based*: a payload that comes back in the
    response proves the input is unsanitised at that injection point.
    No exploitation is ever performed.
    """

    PAYLOADS = {
        "sql_injection": ["' OR '1'='1", "' UNION SELECT null--", "1' ORDER BY 1--"],
        "xss": ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        "path_traversal": ["../../etc/passwd", "..%2f..%2fetc%2fpasswd"],
        "command_injection": ["; ls", "&& whoami", "$(id)"],
    }

    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.ethics = EthicalUsageValidator(output_callback)

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def scan_url(self, url, scan_types=None, authorized=False):
        if not REQUESTS_OK:
            self.log("Requests library not available - scanner disabled.", "error")
            return {}
        ok, msg = self.ethics.validate(url, authorized)
        if not ok:
            self.log(msg, "error")
            return {}
        self.log(msg, "success")
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]

        types = scan_types or list(self.PAYLOADS.keys())
        results = {"url": url, "host": host, "timestamp": datetime.now().isoformat(),
                   "vulnerabilities": [], "total_tests": 0, "vulnerable_tests": 0}
        self.log(f"Vulnerability scan started on: {url}", "info")
        for vtype in types:
            for payload in self.PAYLOADS.get(vtype, [])[:3]:
                results["total_tests"] += 1
                try:
                    sep = "&" if "?" in url else "?"
                    r = requests.get(f"{url}{sep}test={payload}", timeout=10,
                                     allow_redirects=False,
                                     headers={"User-Agent": "SecurityToolkit/2.0"})
                    if payload in r.text:
                        results["vulnerabilities"].append({
                            "type": vtype, "payload": payload,
                            "url": r.url, "status_code": r.status_code,
                            "evidence": "Payload reflected in response"})
                        results["vulnerable_tests"] += 1
                        self.log(f"Potential {vtype} found (reflected)!", "warning")
                except Exception as exc:
                    self.log(f"Request failed: {exc}", "error")
        self.log(f"Finished: {results['vulnerable_tests']}/{results['total_tests']} tests positive", "info")
        if results["vulnerabilities"]:
            self.log(f"{len(results['vulnerabilities'])} potential vulnerabilities reported.", "error")
        else:
            self.log("No obvious vulnerabilities detected.", "success")
        return results
