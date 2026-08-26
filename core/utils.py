"""Shared helpers: formatting, validation, URLs."""
import os
import re
import socket
from datetime import datetime


def now_str(fmt="%H:%M:%S"):
    return datetime.now().strftime(fmt)


def full_stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def fmt_size(num):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024.0:
            return f"{num:.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} PB"


def fmt_duration(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


def is_private_host(host):
    """True when host is localhost / a private or link-local address.
    Accepts bare hosts, 'host:port' and full http(s) URLs."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    if "://" in host:
        from urllib.parse import urlparse
        parsed = urlparse(host)
        host = parsed.hostname or host
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    host = host.rstrip("/")
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    if a == 10 or a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def normalize_url(url):
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url.rstrip("/")
