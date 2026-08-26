"""Ethical usage validator: keeps the toolkit on authorised targets."""
from . import utils


class EthicalUsageValidator:
    """Prevents unauthorised testing of public hosts.

    Private / loopback targets (localhost, 10.*, 172.16-31.*, 192.168.*,
    169.254.*) are always allowed.  Public hosts require the user to
    explicitly declare authorisation in the GUI before any scan launches.
    """

    def __init__(self, output_callback=None):
        self.output_callback = output_callback

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def validate(self, target, authorized=False):
        """Return (ok, message)."""
        target = (target or "").strip()
        if not target:
            return False, "Empty target."
        if utils.is_private_host(target):
            return True, f"OK - private/loopback target: {target}"
        if authorized:
            return True, f"OK - public target with declared authorisation: {target}"
        return False, (
            f"BLOCKED: '{target}' is a public host. Ethical use requires explicit "
            "authorisation - tick the 'I am authorised to test this target' box "
            "or use a private/loopback target."
        )
