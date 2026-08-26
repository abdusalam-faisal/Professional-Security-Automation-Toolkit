"""SSL/TLS certificate inspection: validity, expiry, cipher, protocol."""
import socket
import ssl
from datetime import datetime

from . import utils


class SSLChecker:
    """Connects with a verifying context and reports certificate facts."""

    def __init__(self, output_callback=None):
        self.output_callback = output_callback

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def check_ssl(self, hostname, port=443):
        self.log(f"Checking SSL/TLS for {hostname}:{port}", "info")
        results = {"hostname": hostname, "port": port,
                   "checked_at": datetime.now().isoformat(),
                   "valid": False, "certificate": {}, "warnings": [], "errors": []}
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)
        try:
            with context.wrap_socket(raw, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                cert = ssock.getpeercert()
                results["valid"] = True
                for key in ("subject", "issuer", "serialNumber", "notBefore", "notAfter", "version"):
                    if key in cert:
                        results["certificate"][key] = cert[key]
                if "notAfter" in cert:
                    try:
                        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days = (expiry - datetime.now()).days
                        results["days_remaining"] = days
                        if days < 0:
                            results["errors"].append(f"Certificate expired {-days} days ago")
                            self.log(f"Certificate EXPIRED {-days} days ago", "error")
                        elif days < 30:
                            results["warnings"].append(f"Certificate expires in {days} days")
                            self.log(f"Certificate expires in {days} days", "warning")
                        else:
                            results["days_remaining"] = days
                            self.log(f"Certificate valid for {days} days", "success")
                    except Exception:
                        pass
                cipher = ssock.cipher()
                if cipher:
                    results["cipher"] = {"name": cipher[0], "version": cipher[1], "bits": cipher[2]}
                    results["protocol"] = ssock.version()
                    self.log(f"Cipher: {cipher[0]} ({cipher[2]} bits) | {ssock.version()}", "info")
                self.log("SSL/TLS handshake successful", "success")
        except ssl.SSLCertVerificationError as exc:
            results["errors"].append(f"Verification failed: {exc}")
            self.log(f"Certificate verification failed: {exc}", "error")
        except Exception as exc:
            results["errors"].append(f"Connection failed: {exc}")
            self.log(f"SSL check failed: {exc}", "error")
        return results
