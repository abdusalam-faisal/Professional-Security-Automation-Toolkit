"""Cryptographic hash verification, streaming baseline & integrity audit."""
import hashlib
import json
import os
import time
from datetime import datetime

from . import utils


class EnhancedFileHashChecker:
    """MD5/SHA-1/SHA-256/SHA-512/SHA3-256 with progress, verify & baselines."""

    SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512", "sha3_256"]
    CHUNK = 65536

    def __init__(self, output_callback=None):
        self.output_callback = output_callback

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def calculate_hash(self, file_path, algorithm="sha256"):
        """Streaming hash with progress reporting (O(1) memory)."""
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            self.log(f"Unsupported algorithm: {algorithm}", "error")
            return None
        if not os.path.isfile(file_path):
            self.log(f"File not found: {file_path}", "error")
            return None
        try:
            algorithm = "sha3_256" if algorithm == "sha3_256" and hasattr(hashlib, "sha3_256") else algorithm
            hash_func = getattr(hashlib, algorithm)()
        except Exception as exc:
            self.log(f"Cannot initialise {algorithm}: {exc}", "error")
            return None

        size = os.path.getsize(file_path)
        self.log(f"Calculating {algorithm.upper()} hash for: {os.path.basename(file_path)}", "info")
        self.log(f"File size: {utils.fmt_size(size)}", "info")
        start = time.time()
        processed = 0
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK)
                    if not chunk:
                        break
                    hash_func.update(chunk)
                    processed += len(chunk)
                    if size and int((processed / size) * 100) % 25 == 0:
                        speed = processed / max(time.time() - start, 1e-6) / 1024
                        self.log(f"   Progress: {processed / size * 100:.0f}% | Speed: {speed:.0f} KB/s", "info")
        except PermissionError:
            self.log(f"Permission denied: {file_path}", "error")
            return None
        except Exception as exc:
            self.log(f"Hash error: {exc}", "error")
            return None

        digest = hash_func.hexdigest()
        self.log(f"{algorithm.upper()} hash calculated in {time.time() - start:.2f}s", "success")
        self.log(f"Hash: {digest}", "info")
        return digest

    def verify_file(self, file_path, expected_hash=None, algorithm="sha256"):
        digest = self.calculate_hash(file_path, algorithm)
        if not digest:
            return False
        if not expected_hash:
            self.log("Hash calculated (no verification requested)", "info")
            return True
        expected = expected_hash.strip().lower()
        if digest == expected:
            self.log("INTEGRITY VERIFIED - Hashes match perfectly!", "success")
            self.log(f"   File: {os.path.basename(file_path)} | Algorithm: {algorithm.upper()}", "info")
            self.log(f"   Expected: {expected[:16]}... | Calculated: {digest[:16]}...", "info")
            return True
        self.log("INTEGRITY COMPROMISED - Hash mismatch detected!", "error")
        self.log(f"   Expected: {expected}", "error")
        self.log(f"   Calculated: {digest}", "error")
        pos = next((i for i, (a, b) in enumerate(zip(expected, digest)) if a != b), None)
        if pos is not None:
            self.log(f"   First mismatch at position: {pos + 1}", "error")
        return False

    def create_directory_baseline(self, directory, algorithm="sha256"):
        """Hash every file under a directory into a JSON baseline."""
        if not os.path.isdir(directory):
            self.log(f"Invalid directory: {directory}", "error")
            return None
        self.log(f"Creating baseline for: {directory}", "info")
        baseline = {
            "directory": os.path.abspath(directory),
            "timestamp": datetime.now().isoformat(),
            "algorithm": algorithm,
            "files": [],
        }
        all_files = []
        for root, _, names in os.walk(directory):
            for name in names:
                all_files.append(os.path.join(root, name))
        self.log(f"Found {len(all_files)} files to process", "info")
        total = len(all_files)
        for i, path in enumerate(all_files, 1):
            rel = os.path.relpath(path, directory)
            self.log(f"   [{i}/{total}] {rel}", "info")
            digest = self.calculate_hash(path, algorithm)
            if digest:
                baseline["files"].append({
                    "path": rel,
                    "hash": digest,
                    "size": os.path.getsize(path),
                    "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                })
        out = os.path.join(os.path.expanduser("~"), "security_reports",
                           f"baseline_{utils.full_stamp()}.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)
        self.log(f"Baseline created: {out} ({len(baseline['files'])} files)", "success")
        return out

    def compare_baseline(self, baseline_path, directory=None):
        """Audit a directory against a saved baseline (changed/new/deleted)."""
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline = json.load(f)
        except Exception as exc:
            self.log(f"Cannot read baseline: {exc}", "error")
            return None
        directory = directory or baseline.get("directory", "")
        algorithm = baseline.get("algorithm", "sha256")
        self.log(f"Auditing '{directory}' against baseline {os.path.basename(baseline_path)}", "info")
        audit = {"changed": [], "new": [], "deleted": [], "unchanged": 0}
        recorded = {os.path.join(directory, e["path"]): e for e in baseline.get("files", [])}
        current = set()
        for root, _, names in os.walk(directory):
            for name in names:
                current.add(os.path.join(root, name))
        for path in sorted(current):
            rel = os.path.relpath(path, directory)
            if path not in recorded:
                audit["new"].append(rel)
                self.log(f"NEW file: {rel}", "warning")
            else:
                digest = self.calculate_hash(path, algorithm)
                if digest and digest != recorded[path]["hash"]:
                    audit["changed"].append(rel)
                    self.log(f"MODIFIED: {rel}", "error")
                else:
                    audit["unchanged"] += 1
        for path in sorted(set(recorded) - current):
            rel = os.path.relpath(path, directory)
            audit["deleted"].append(rel)
            self.log(f"DELETED: {rel}", "warning")
        self.log(f"Audit done - {audit['unchanged']} unchanged, {len(audit['changed'])} modified, "
                 f"{len(audit['new'])} new, {len(audit['deleted'])} deleted", "info")
        return audit
