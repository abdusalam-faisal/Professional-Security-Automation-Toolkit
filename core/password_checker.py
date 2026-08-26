"""Password strength analysis with entropy calculation."""
import math
import re


class PasswordStrengthChecker:
    COMMON = [
        "password", "123456", "12345678", "123456789", "qwerty", "admin",
        "welcome", "password123", "letmein", "monkey", "dragon", "abc123",
        "111111", "iloveyou", "sunshine", "princess", "football", "login",
        "secret", "passw0rd", "master", "hello", "654321", "000000",
    ]

    def __init__(self, output_callback=None):
        self.output_callback = output_callback

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def check_password(self, password):
        """Return dict with score, strength, entropy and feedback."""
        if not password:
            self.log("Empty password.", "warning")
            return None
        pwd = password
        checks = {
            "length>=12": len(pwd) >= 12,
            "length>=8": len(pwd) >= 8,
            "uppercase": bool(re.search(r"[A-Z]", pwd)),
            "lowercase": bool(re.search(r"[a-z]", pwd)),
            "digits": bool(re.search(r"\d", pwd)),
            "special": bool(re.search(r"[^A-Za-z0-9]", pwd)),
            "not_common": pwd.lower() not in self.COMMON,
        }
        score = 0
        feedback = []
        if len(pwd) >= 12:
            score += 3
            feedback.append("Length 12+: excellent")
        elif len(pwd) >= 8:
            score += 2
            feedback.append("Length 8+: acceptable")
        else:
            feedback.append("Length < 8: too short")
        if checks["not_common"]:
            score += 2
            feedback.append("Not a common password")
        else:
            score = 0
            feedback.append("Password is far too common")
            if checks["uppercase"]:
                score += 1
            if checks["lowercase"]:
                score += 1
            if checks["digits"]:
                score += 1
            if checks["special"]:
                score += 1
        variety = sum(checks[k] for k in ("uppercase", "lowercase", "digits", "special"))
        score += variety
        for label, present in (("uppercase", checks["uppercase"]), ("lowercase", checks["lowercase"]),
                               ("digits", checks["digits"]), ("special", checks["special"])):
            feedback.append(f"{'Has' if present else 'Missing'} {label}")

        charset_size = 0
        if checks["uppercase"]:
            charset_size += 26
        if checks["lowercase"]:
            charset_size += 26
        if checks["digits"]:
            charset_size += 10
        if checks["special"]:
            charset_size += 33
        entropy = len(pwd) * math.log2(max(charset_size, 1)) if charset_size else 0.0

        if score >= 9:
            strength, color = "Strong", "success"
        elif score >= 6:
            strength, color = "Moderate", "warning"
        else:
            strength, color = "Weak", "error"
        results = {"score": min(score, 12), "strength": strength, "entropy_bits": round(entropy, 1),
                   "feedback": feedback, "checks": checks}
        self.log(f"Password Strength: {strength} | Score {min(score, 12)}/12 | Entropy {entropy:.1f} bits", color)
        for item in feedback:
            self.log(f"   - {item}", "info")
        return results
