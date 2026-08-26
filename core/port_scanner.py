"""Multi-threaded TCP port scanner with service detection & banner grabbing."""
import queue
import socket
import threading
import time

from .threads import ThreadPoolManager


class EnhancedPortScanner:
    """TCP connect-scan with service fingerprinting and banners.

    Implements the doc's ``threaded_scan`` algorithm (queue + worker pool,
    O(n) time with O(k) threads).
    """

    def __init__(self, output_callback=None, max_threads=100, timeout=1.0):
        self.output_callback = output_callback
        self.max_threads = max_threads
        self.timeout = timeout
        self.pool = ThreadPoolManager(output_callback, max_workers=max_threads)
        self.last_open_ports = []
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            115: "SFTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis",
            9200: "Elasticsearch", 9300: "Elasticsearch-Cluster"
        }

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def parse_ports(self, port_range):
        """Accept '1-1024', '80,443,8080' or a single number."""
        pr = str(port_range).strip()
        if "-" in pr:
            a, b = pr.split("-")
            return list(range(int(a), int(b) + 1))
        if "," in pr:
            return [int(p) for p in pr.split(",") if p.strip()]
        return [int(pr)]

    def scan_port(self, target, port):
        """TCP connect probe; returns (open, service, banner)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((target, port)) != 0:
                return False, None, None
            banner = self._grab_banner(sock, port)
            service = self.common_ports.get(port, "Unknown")
            return True, service, banner
        except Exception:
            return False, None, None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            if port in (80, 8080, 1880):
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                sock.send(b"QUIT\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-PythonScanner\r\n")
            elif port == 25:
                sock.send(b"EHLO example.com\r\n")
            data = sock.recv(1024)
            return data.decode("utf-8", errors="ignore").strip()[:200] or None
        except Exception:
            return None

    def threaded_scan(self, target, port_range="1-1024", max_threads=None, progress_cb=None):
        """Queue-based concurrent scan. Returns list of (port, service, banner)."""
        ports = self.parse_ports(port_range)
        if not ports:
            self.log("Invalid port range.", "error")
            return []
        threads = max_threads or self.max_threads
        self.log(f"Starting advanced port scan on {target}", "info")
        self.log(f"Scanning range: {port_range} ({len(ports)} ports, {threads} threads)", "info")

        found, lock = [], threading.Lock()
        start = time.time()
        checked = {"n": 0}

        def check(port):
            is_open, service, banner = self.scan_port(target, port)
            with lock:
                checked["n"] += 1
                if progress_cb:
                    progress_cb(checked["n"], len(ports))
                if is_open:
                    found.append((port, service, banner))
                    msg = f"Port {port}/TCP open - {service}"
                    if banner:
                        msg += f" | Banner: {str(banner)[:50]}..."
                    self.log(msg, "success")

        self.pool.map(ports, check, workers=threads)
        elapsed = time.time() - start
        self.log(f"Scan completed in {elapsed:.2f}s. Open ports found: {len(found)}", "info")
        self.last_open_ports = found
        if found:
            self.log("\nOpen Ports Summary:", "info")
            self.log("=" * 60, "info")
            for port, service, banner in sorted(found):
                banner_preview = f" | {banner[:30]}..." if banner else ""
                self.log(f"  {port:>5}/TCP - {service:<20}{banner_preview}", "info")
        return found
