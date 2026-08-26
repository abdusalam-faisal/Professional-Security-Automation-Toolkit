"""Web directory enumeration with custom wordlist support."""
import os
import re
import time

from .threads import ThreadPoolManager

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

DEFAULT_WORDLIST = [
    "admin", "administrator", "backup", "bak", "config", "configuration",
    "database", "db", "download", "error", "files", "images", "img",
    "includes", "index.php", "logs", "media", "modules", "private",
    "secret", "source", "sql", "stats", "temp", "test", "uploads", "web",
    "wp-admin", "wp-content", "wp-includes", ".git", ".env", ".htaccess",
    "api", "v1", "docs", "robots.txt", "sitemap.xml", "phpinfo.php",
]


class DirectoryBruteforcer:
    """Enumeration using a default wordlist or a user-supplied one."""

    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.pool = ThreadPoolManager(output_callback, max_workers=20)
        self.last_found = []

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    @staticmethod
    def load_wordlist(path):
        if not path or not os.path.isfile(path):
            return None
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line.lstrip("/"))
        return words

    def brute_force(self, base_url, wordlist_path=None, extensions=None, max_threads=20):
        if not REQUESTS_OK:
            self.log("Requests library not available - directory scanner disabled.", "error")
            return []
        base_url = base_url.rstrip("/")
        words = self.load_wordlist(wordlist_path) or DEFAULT_WORDLIST
        if not words:
            self.log("Empty wordlist.", "error")
            return []

        targets = list(words)
        if extensions:
            extra = []
            for w in words:
                for ext in extensions:
                    extra.append(f"{w}.{ext.strip('.')}")
            targets.extend(extra)

        self.log(f"Directory enumeration started on: {base_url} "
                 f"({len(targets)} targets, {max_threads} threads)", "info")

        found, lock = [], __import__("threading").Lock()
        start = time.time()

        def probe(word):
            url = f"{base_url}/{word}"
            try:
                r = requests.get(url, timeout=6, allow_redirects=False,
                                 headers={"User-Agent": "SecurityToolkit/2.0"})
                with lock:
                    if r.status_code == 200 and not re.match(r"^text/html", r.headers.get("Content-Type", "")):
                        found.append((url, "200", len(r.content)))
                        self.log(f"Found: {url} (200, {len(r.content)}b)", "success")
                    elif r.status_code in (301, 302, 307):
                        found.append((url, str(r.status_code), 0))
                        self.log(f"Redirect: {url} ({r.status_code})", "warning")
                    elif r.status_code == 403:
                        found.append((url, "403", 0))
                        self.log(f"Forbidden: {url} (403)", "warning")
            except Exception:
                pass

        self.pool.map(targets, probe, workers=max_threads)
        elapsed = time.time() - start
        self.log(f"Enumeration finished in {elapsed:.2f}s - {len(found)} accessible items", "info")
        self.last_found = found
        return found
