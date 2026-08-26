"""Session management: persist and restore GUI configuration."""
import json
import os

DEFAULTS = {
    "theme": "Light",
    "target": "127.0.0.1",
    "port_range": "1-1024",
    "threads": 100,
    "timeout": 2,
    "dir_url": "http://localhost",
    "dir_wordlist": "",
    "vuln_url": "http://localhost",
    "http_url": "https://example.com",
    "ssl_host": "google.com",
    "ssl_port": "443",
    "sniff_count": "50",
    "sniff_timeout": "30",
    "sniff_filter": "",
    "sniff_interface": "",
    "log_file": "",
    "reports_dir": "",
    "authorize_public": False,
}


class SessionManager:
    """Implements the doc's 'session management: save and restore scanning
    configurations'.  Saves/loads a JSON file in the user home folder."""

    def __init__(self, path=None):
        self.path = path or os.path.join(
            os.path.expanduser("~"), ".security_toolkit_session.json")

    def save(self, state):
        try:
            clean = {k: state.get(k, DEFAULTS.get(k)) for k in DEFAULTS}
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(clean, f, indent=2)
            return self.path
        except Exception:
            return None

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = dict(DEFAULTS)
            merged.update(data)
            return merged
        except Exception:
            return dict(DEFAULTS)
