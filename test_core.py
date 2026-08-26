"""Functional smoke tests for the core engine (no GUI). Run: python3 test_core.py"""
import http.server
import os
import socket
import socketserver
import sys
import tempfile
import threading

# find a free port at runtime (avoids conflicts with stale test servers)
_probe = socket.socket()
_probe.bind(("127.0.0.1", 0))
PORT = _probe.getsockname()[1]
_probe.close()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = []


def cb(msg, level="info"):
    print(f"    [{level}] {str(msg)[:110]}")


class EchoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/echo"):
            body = self.path.split("?", 1)[1].encode() if "?" in self.path else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def main():
    tmp = tempfile.mkdtemp(prefix="tk_test_")
    with open(os.path.join(tmp, "admin"), "w") as f:
        f.write("secret-content-123")
    old = os.getcwd()
    os.chdir(tmp)
    srv = socketserver.TCPServer(("127.0.0.1", PORT), EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # 1) port scanner ---------------------------------------------------------
    from core.port_scanner import EnhancedPortScanner
    ps = EnhancedPortScanner(cb, max_threads=10)
    found = ps.threaded_scan("127.0.0.1", f"{PORT}-{PORT + 2}", max_threads=5)
    assert any(p == PORT for p, _, _ in found), f"port {PORT} not found: {found}"
    print("  [PORT SCAN] 18080 detected:", found)
    PASS.append("port_scanner")

    # 2) file hasher ----------------------------------------------------------
    from core.file_hash import EnhancedFileHashChecker
    fh = EnhancedFileHashChecker(cb)
    digest = fh.calculate_hash(os.path.join(tmp, "admin"), "sha256")
    assert digest and len(digest) == 64, digest
    assert fh.verify_file(os.path.join(tmp, "admin"), digest, "sha256") is True
    assert fh.verify_file(os.path.join(tmp, "admin"), "0" * 64, "sha256") is False
    base = fh.create_directory_baseline(tmp, "sha256")
    assert base and os.path.isfile(base)
    audit = fh.compare_baseline(base, tmp)
    assert audit and audit["unchanged"] >= 1 and not audit["changed"], audit
    print("  [FILE HASH] sha256 + verify + baseline + audit OK")
    PASS.append("file_hasher")

    # 3) directory scanner -----------------------------------------------------
    from core.directory_scanner import DirectoryBruteforcer
    ds = DirectoryBruteforcer(cb)
    hits = ds.brute_force(f"http://127.0.0.1:{PORT}", max_threads=8)
    assert any("admin" in url for url, _, _ in hits), hits
    print("  [DIR SCANNER] admin found:", hits[:2])
    PASS.append("directory_scanner")

    # 4) vulnerability scanner (reflection via /echo) --------------------------
    from core.vuln_scanner import BasicVulnerabilityScanner
    vs = BasicVulnerabilityScanner(cb)
    res = vs.scan_url(f"http://127.0.0.1:{PORT}/echo")
    assert res and res["vulnerable_tests"] >= 1, res
    print("  [VULN SCANNER] reflected payloads:", res["vulnerable_tests"], "/", res["total_tests"])
    PASS.append("vuln_scanner")

    # 5) HTTP auditor -----------------------------------------------------------
    from core.http_auditor import EnhancedHTTPHeaderAuditor
    ha = EnhancedHTTPHeaderAuditor(cb)
    hr = ha.audit_url(f"http://127.0.0.1:{PORT}/")
    assert hr and hr["grade"] == "F" and len(hr["missing_headers"]) == 8, hr
    print("  [HTTP AUDITOR] grade", hr["grade"], "missing", len(hr["missing_headers"]))
    PASS.append("http_auditor")

    # 6) log parser -------------------------------------------------------------
    from core.log_parser import AdvancedLogParser
    lp = AdvancedLogParser(cb)
    sample = (
        '192.168.1.5 - - [24/Aug/2026:10:00:01] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200\n'
        '10.0.0.2 - - [24/Aug/2026:10:00:02] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 404\n'
        '203.0.113.9 - - [24/Aug/2026:10:00:03] "POST /login HTTP/1.1" 401 - "Failed password for admin"\n'
        '198.51.100.7 - - [24/Aug/2026:10:00:04] "GET /admin.php?user=admin\'-- HTTP/1.1" 200\n'
        "2001:db8::1 - - [24/Aug/2026:10:00:05] \"<script>alert('x')</script>\" 400\n"
    )
    findings = lp.analyze(sample, "sample.log")
    assert findings["summary"]["suspicious_activity"] >= 4, findings
    assert "sql_injection" in findings["summary"]["attacks_by_type"]
    lp.report(findings)
    print("  [LOG PARSER] suspicious:", findings["summary"]["suspicious_activity"])
    PASS.append("log_parser")

    # 7) password checker ---------------------------------------------------------
    from core.password_checker import PasswordStrengthChecker
    pc = PasswordStrengthChecker(cb)
    weak = pc.check_password("password")
    strong = pc.check_password("Tr0ub4dor&3!xK9")
    assert weak and weak["strength"] == "Weak", weak
    assert strong and strong["strength"] == "Strong", strong
    assert strong["entropy_bits"] > 60, strong
    print("  [PASSWORD] weak:", weak["score"], "| strong:", strong["score"], "entropy", strong["entropy_bits"])
    PASS.append("password_checker")

    # 8) SSL checker ---------------------------------------------------------------
    from core.ssl_checker import SSLChecker
    sc = SSLChecker(cb)
    ssl_res = sc.check_ssl("example.com", 443)
    assert ssl_res.get("valid") is True or ssl_res.get("errors"), ssl_res
    print("  [SSL] valid:", ssl_res.get("valid"), "| errors:", ssl_res.get("errors"))
    PASS.append("ssl_checker")

    srv.shutdown()
    os.chdir(old)
    print("\nALL CORE TESTS PASSED:", PASS)


if __name__ == "__main__":
    main()
