#!/usr/bin/env python3
"""
Enhanced Python Security Automation Toolkit - Professional GUI Version with Scrollbars
"""

import sys
import os
import socket
import threading
import queue
import hashlib
import re
import json
import time
import ssl
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import tkinter.font as tkFont
from tkinter import simpledialog

# Import optional dependencies with proper error handling
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ============================================================================
# ENHANCED CORE TOOL CLASSES (Keep all existing classes)
# ============================================================================

class ThreadPoolManager:
    """Enhanced thread pool with dynamic scaling and monitoring"""
    
    def __init__(self, output_callback=None, max_workers=50):
        self.output_callback = output_callback
        self.max_workers = max_workers
        self.task_queue = queue.Queue()
        self.workers = []
        self.active_count = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def submit_task(self, task_func, *args, **kwargs):
        """Submit task with error handling wrapper"""
        def wrapped_task():
            try:
                task_func(*args, **kwargs)
                self.completed_tasks += 1
            except Exception as e:
                self.failed_tasks += 1
                self.log(f"Task failed: {e}", "error")
            finally:
                self.active_count -= 1
        
        self.task_queue.put(wrapped_task)
        self._scale_workers()
    
    def _scale_workers(self):
        """Dynamically adjust worker count"""
        while (len(self.workers) < self.max_workers and 
               self.active_count < self.task_queue.qsize()):
            worker = threading.Thread(target=self._worker_loop, daemon=True)
            worker.start()
            self.workers.append(worker)
            self.active_count += 1
    
    def _worker_loop(self):
        """Worker thread processing loop"""
        while True:
            try:
                task = self.task_queue.get(timeout=1)
                task()
                self.task_queue.task_done()
            except queue.Empty:
                break
    
    def wait_completion(self):
        """Wait for all tasks to complete"""
        self.task_queue.join()


class EnhancedPortScanner:
    """Advanced port scanner with service detection and banner grabbing"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            115: "SFTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis",
            9200: "Elasticsearch", 9300: "Elasticsearch-Cluster"
        }
        self.banner_timeout = 2
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def scan_port(self, target, port, timeout=1, scan_type="connect"):
        """Scan a single port with optional service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open - try to get banner
                service_info = self._get_service_info(sock, target, port)
                sock.close()
                return True, service_info
            else:
                sock.close()
                return False, None
        except:
            return False, None
    
    def _get_service_info(self, sock, target, port):
        """Attempt to get service banner/version"""
        try:
            sock.settimeout(self.banner_timeout)
            
            # Send generic probe
            if port == 80 or port == 443:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                sock.send(b"QUIT\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-PythonScanner\r\n")
            elif port == 25:
                sock.send(b"EHLO example.com\r\n")
            
            # Receive response
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except:
            return None
    
    def threaded_scan(self, target, port_range="1-1024", max_threads=100):
        """Multi-threaded port scanning"""
        self.log(f"🚀 Starting advanced port scan on {target}", "info")
        self.log(f"📊 Scanning range: {port_range}", "info")
        
        # Parse port range
        if "-" in port_range:
            start_port, end_port = map(int, port_range.split("-"))
            ports = range(start_port, end_port + 1)
        elif "," in port_range:
            ports = [int(p) for p in port_range.split(",")]
        else:
            ports = [int(port_range)]
        
        open_ports = []
        q = queue.Queue()
        
        # Add ports to queue
        for port in ports:
            q.put(port)
        
        def worker():
            while not q.empty():
                port = q.get()
                is_open, banner = self.scan_port(target, port)
                
                if is_open:
                    service = self.common_ports.get(port, "Unknown")
                    open_ports.append((port, service, banner))
                    
                    if banner:
                        self.log(f"✅ Port {port}/TCP open - {service} | Banner: {banner[:50]}...", "success")
                    else:
                        self.log(f"✅ Port {port}/TCP open - {service}", "success")
                
                q.task_done()
        
        # Create worker threads
        threads = []
        for _ in range(min(max_threads, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        q.join()
        
        self.log(f"📋 Scan completed. Open ports found: {len(open_ports)}", "info")
        
        if open_ports:
            self.log("\n📊 Open Ports Summary:", "info")
            self.log("=" * 60, "info")
            for port, service, banner in sorted(open_ports, key=lambda x: x[0]):
                banner_preview = f" | {banner[:30]}..." if banner else ""
                self.log(f"  {port:>5}/TCP - {service:<20}{banner_preview}", "info")
        
        return open_ports


class EnhancedFileHashChecker:
    """Professional file integrity verification with multiple algorithms"""
    
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.baselines = {}
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def calculate_hash(self, file_path, algorithm='sha256', chunk_size=65536):
        """Calculate file hash with progress tracking"""
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            self.log(f"❌ Unsupported algorithm: {algorithm}", "error")
            return None
        
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.log(f"❌ File not found: {file_path}", "error")
                return None
            
            # Get file size for progress tracking
            file_size = os.path.getsize(file_path)
            
            # Initialize hash function
            if algorithm == 'sha3_256' and hasattr(hashlib, 'sha3_256'):
                hash_func = hashlib.sha3_256()
            else:
                hash_func = getattr(hashlib, algorithm)()
            
            self.log(f"🔍 Calculating {algorithm.upper()} hash for: {os.path.basename(file_path)}", "info")
            self.log(f"📏 File size: {self._format_size(file_size)}", "info")
            
            processed = 0
            start_time = time.time()
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    hash_func.update(chunk)
                    processed += len(chunk)
                    
                    # Progress reporting every 10%
                    progress = (processed / file_size) * 100
                    if int(progress) % 20 == 0 and progress > 0:
                        elapsed = time.time() - start_time
                        speed = processed / elapsed / 1024 if elapsed > 0 else 0
                        self.log(f"   Progress: {progress:.1f}% | Speed: {speed:.1f} KB/s", "info")
            
            calculated_hash = hash_func.hexdigest()
            elapsed = time.time() - start_time
            
            self.log(f"✅ {algorithm.upper()} hash calculated in {elapsed:.2f}s", "success")
            self.log(f"🔑 Hash: {calculated_hash}", "info")
            
            return calculated_hash
            
        except PermissionError:
            self.log(f"❌ Permission denied: {file_path}", "error")
            return None
        except Exception as e:
            self.log(f"❌ Error calculating hash: {str(e)}", "error")
            return None
    
    def verify_file(self, file_path, expected_hash=None, algorithm='sha256'):
        """Enhanced file verification with detailed reporting"""
        self.log(f"🔍 Verifying file integrity: {os.path.basename(file_path)}", "info")
        
        calculated_hash = self.calculate_hash(file_path, algorithm)
        
        if not calculated_hash:
            return False
        
        if expected_hash:
            # Clean the expected hash (remove spaces, convert to lowercase)
            expected_hash_clean = expected_hash.strip().lower()
            calculated_hash_lower = calculated_hash.lower()
            
            is_match = calculated_hash_lower == expected_hash_clean
            
            if is_match:
                self.log(f"✅ INTEGRITY VERIFIED - Hashes match perfectly!", "success")
                self.log(f"   File: {os.path.basename(file_path)}", "info")
                self.log(f"   Algorithm: {algorithm.upper()}", "info")
                self.log(f"   Expected: {expected_hash_clean[:16]}...", "info")
                self.log(f"   Calculated: {calculated_hash_lower[:16]}...", "info")
                return True
            else:
                self.log(f"❌ INTEGRITY COMPROMISED - Hash mismatch detected!", "error")
                self.log(f"   File: {os.path.basename(file_path)}", "error")
                self.log(f"   Algorithm: {algorithm.upper()}", "error")
                self.log(f"   Expected: {expected_hash_clean}", "error")
                self.log(f"   Calculated: {calculated_hash}", "error")
                
                # Show where the mismatch occurs
                mismatch_pos = self._find_mismatch_position(calculated_hash_lower, expected_hash_clean)
                if mismatch_pos:
                    self.log(f"   Mismatch at position: {mismatch_pos}", "error")
                
                return False
        else:
            # Just return the calculated hash
            self.log(f"📝 File hash calculated (no verification performed)", "info")
            self.log(f"   Hash: {calculated_hash}", "info")
            return True
    
    def create_directory_baseline(self, directory_path, algorithm='sha256'):
        """Create a baseline of all files in a directory"""
        if not os.path.isdir(directory_path):
            self.log(f"❌ Invalid directory: {directory_path}", "error")
            return None
        
        self.log(f"📁 Creating baseline for directory: {directory_path}", "info")
        
        baseline = {
            'directory': directory_path,
            'timestamp': datetime.now().isoformat(),
            'algorithm': algorithm,
            'files': [],
            'total_size': 0
        }
        
        total_files = 0
        file_count = 0
        
        # Count total files first
        for root, dirs, files in os.walk(directory_path):
            total_files += len(files)
        
        self.log(f"📊 Found {total_files} files to process", "info")
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    relative_path = os.path.relpath(file_path, directory_path)
                    file_count += 1
                    
                    self.log(f"   Processing file {file_count}/{total_files}: {relative_path}", "info")
                    
                    file_hash = self.calculate_hash(file_path, algorithm)
                    if file_hash:
                        file_size = os.path.getsize(file_path)
                        baseline['files'].append({
                            'path': relative_path,
                            'hash': file_hash,
                            'size': file_size,
                            'modified': os.path.getmtime(file_path),
                            'created': os.path.getctime(file_path)
                        })
                        baseline['total_size'] += file_size
                except Exception as e:
                    self.log(f"   ⚠️ Skipped {file}: {str(e)}", "warning")
        
        baseline['file_count'] = len(baseline['files'])
        
        # Save baseline to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        baseline_file = f"baseline_{os.path.basename(directory_path)}_{timestamp}.json"
        
        try:
            with open(baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2, default=str)
            
            self.log(f"✅ Baseline created successfully!", "success")
            self.log(f"📊 Summary:", "info")
            self.log(f"   Files: {baseline['file_count']}", "info")
            self.log(f"   Total size: {self._format_size(baseline['total_size'])}", "info")
            self.log(f"   Baseline saved to: {baseline_file}", "info")
            
            return baseline_file 
        except Exception as e:
            self.log(f"❌ Error saving baseline: {str(e)}", "error")
            return None
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def _find_mismatch_position(self, hash1, hash2):
        """Find the first position where hashes differ"""
        for i, (c1, c2) in enumerate(zip(hash1, hash2)):
            if c1 != c2:
                return i + 1
        return None


class DirectoryBruteforcer:
    """Enhanced directory bruteforcer"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        if not REQUESTS_AVAILABLE:
            self.log("Directory bruteforcer requires 'requests' library", "error")
        
        self.common_dirs = [
            "admin", "backup", "config", "database", "download",
            "error", "files", "images", "includes", "logs",
            "media", "modules", "private", "secret", "source",
            "sql", "stats", "temp", "test", "upload", "web"
        ]
    
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def brute_force(self, base_url, wordlist=None, extensions=None, max_threads=20):
        if not REQUESTS_AVAILABLE:
            self.log("Requests library not available", "error")
            return []
        
        self.log(f"Starting directory enumeration on: {base_url}", "info")
        
        targets = self.common_dirs
        
        found_items = []
        q = queue.Queue()
        
        for target in targets:
            q.put(target)
        
        def worker():
            while not q.empty():
                target = q.get()
                url = f"{base_url}/{target}" if not base_url.endswith('/') else f"{base_url}{target}"
                
                try:
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        found_items.append((url, response.status_code, len(response.content)))
                        self.log(f"Found: {url} (200) - Size: {len(response.content)} bytes", "success")
                    elif response.status_code in [301, 302, 307, 308]:
                        found_items.append((url, response.status_code, 0))
                        self.log(f"Redirect: {url} ({response.status_code})", "warning")
                    elif response.status_code == 403:
                        found_items.append((url, response.status_code, 0))
                        self.log(f"Forbidden: {url} (403)", "warning")
                
                except requests.RequestException:
                    pass
                finally:
                    q.task_done()
        
        threads = []
        for _ in range(min(max_threads, len(targets))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        self.log(f"Testing {len(targets)} targets...", "info")
        start_time = time.time()
        
        q.join()
        elapsed = time.time() - start_time
        self.log(f"Enumeration completed in {elapsed:.2f} seconds", "info")
        self.log(f"Found {len(found_items)} accessible items", "info")
        
        return found_items


class BasicVulnerabilityScanner:
    """Basic vulnerability scanner for common web vulnerabilities"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        if not REQUESTS_AVAILABLE:
            self.log("❌ Vulnerability scanner requires 'requests' library", "error")
        
        self.payloads = {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT null--",
                "1' OR '1'='1",
                "admin'--",
                "1' ORDER BY 1--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "\"onmouseover=\"alert(1)"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'command_injection': [
                "; ls",
                "| dir",
                "&& whoami",
                "`id`",
                "$(cat /etc/passwd)"
            ]
        }
    
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def scan_url(self, url, scan_types=None):
        """Scan a URL for common vulnerabilities"""
        if not REQUESTS_AVAILABLE:
            self.log("❌ Requests library not available", "error")
            return {}
        
        if scan_types is None:
            scan_types = ['sql_injection', 'xss', 'path_traversal']
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'total_tests': 0,
            'vulnerable_tests': 0
        }
        
        self.log(f"🔍 Starting vulnerability scan on: {url}", "info")
        
        for vuln_type in scan_types:
            if vuln_type in self.payloads:
                self.log(f"Testing for {vuln_type}...", "info")
                
                for payload in self.payloads[vuln_type][:3]:  # Limit to 3 payloads per type
                    results['total_tests'] += 1
                    
                    try:
                        # Test GET parameters
                        test_url = f"{url}?test={payload}" if '?' not in url else f"{url}&test={payload}"
                        response = requests.get(test_url, timeout=10, allow_redirects=False)
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            vulnerability = {
                                'type': vuln_type,
                                'payload': payload,
                                'url': test_url,
                                'status_code': response.status_code,
                                'evidence': 'Payload reflected in response'
                            }
                            results['vulnerabilities'].append(vulnerability)
                            results['vulnerable_tests'] += 1
                            self.log(f"⚠️ Potential {vuln_type} found!", "warning")
                            
                    except requests.RequestException as e:
                        self.log(f"Request failed: {str(e)}", "error")
        
        # Generate summary
        self.log(f"📊 Scan completed: {results['vulnerable_tests']}/{results['total_tests']} tests positive", "info")
        
        if results['vulnerabilities']:
            self.log(f"🔴 {len(results['vulnerabilities'])} potential vulnerabilities found!", "error")
            for vuln in results['vulnerabilities']:
                self.log(f"   • {vuln['type']}: {vuln['evidence']}", "warning")
        else:
            self.log(f"✅ No obvious vulnerabilities detected", "success")
        
        return results


class SSLChecker:
    """Check SSL/TLS certificate information and vulnerabilities"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def check_ssl(self, hostname, port=443):
        """Check SSL certificate details"""
        import ssl
        from socket import socket, AF_INET, SOCK_STREAM
        
        self.log(f"🔐 Checking SSL/TLS for {hostname}:{port}", "info")
        
        results = {
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'valid': False,
            'certificate': {},
            'warnings': [],
            'errors': []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Create connection
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(10)
            
            # Wrap socket with SSL
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            ssock.connect((hostname, port))
            
            # Get certificate
            cert = ssock.getpeercert()
            
            # Certificate information
            results['valid'] = True
            results['certificate'] = cert
            
            # Check expiry
            if 'notAfter' in cert:
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days
                
                if days_remaining < 0:
                    results['errors'].append(f"Certificate expired {abs(days_remaining)} days ago")
                elif days_remaining < 7:
                    results['warnings'].append(f"Certificate expires in {days_remaining} days")
                else:
                    self.log(f"✅ Certificate valid for {days_remaining} days", "success")
            
            # Get cipher information
            cipher = ssock.cipher()
            if cipher:
                results['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
                self.log(f"🔒 Cipher: {cipher[0]} ({cipher[2]} bits)", "info")
            
            ssock.close()
            sock.close()
            
            self.log("✅ SSL/TLS connection successful", "success")
            
        except ssl.SSLCertVerificationError as e:
            results['errors'].append(f"Certificate verification failed: {str(e)}")
            self.log(f"❌ Certificate verification failed: {str(e)}", "error")
        except Exception as e:
            results['errors'].append(f"Connection failed: {str(e)}")
            self.log(f"❌ SSL check failed: {str(e)}", "error")
        
        return results


class PasswordStrengthChecker:
    """Check password strength against common criteria"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        
        # Common weak passwords list
        self.common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', '12345678', '123456789', '123123'
        ]
    
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def check_password(self, password):
        """Check password strength and return score"""
        
        score = 0
        feedback = []
        
        self.log(f"🔐 Analyzing password strength", "info")
        
        # Check length
        if len(password) >= 12:
            score += 3
            feedback.append("✅ Length: Good (12+ characters)")
        elif len(password) >= 8:
            score += 2
            feedback.append("⚠️ Length: Acceptable (8+ characters)")
        else:
            feedback.append("❌ Length: Too short (< 8 characters)")
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("❌ Password is too common")
        else:
            score += 2
            feedback.append("✅ Not a common password")
        
        # Check character variety
        checks = {
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digits': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[^A-Za-z0-9]', password))
        }
        
        variety_score = sum(checks.values())
        score += variety_score
        
        for check_name, check_result in checks.items():
            if check_result:
                feedback.append(f"✅ Contains {check_name} characters")
            else:
                feedback.append(f"⚠️ Missing {check_name} characters")
        
        # Determine strength level
        if score >= 8:
            strength = "Strong"
            color = "success"
        elif score >= 5:
            strength = "Moderate"
            color = "warning"
        else:
            strength = "Weak"
            color = "error"
        
        results = {
            'score': score,
            'strength': strength,
            'max_score': 9,
            'feedback': feedback,
            'checks': checks
        }
        
        # Log results
        self.log(f"📊 Password Strength: {strength} ({score}/9)", color)
        for item in feedback:
            self.log(f"   {item}", "info" if '✅' in item else "warning" if '⚠️' in item else "error")
        
        return results


class AdvancedLogParser:
    """Enhanced log parser with timeline analysis and threat detection"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.suspicious_patterns = self._load_security_patterns()
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def _load_security_patterns(self):
        """Load comprehensive security patterns"""
        return {
            'sql_injection': {
                'patterns': [
                    r'union\s+select', r'select.*from', r'insert\s+into',
                    r'delete\s+from', r'update\s+.*set', r'or\s+1\s*=\s*1',
                    r'exec\s*\(', r'xp_cmdshell', r'--', r'/\*.*\*/'
                ],
                'severity': 'critical',
                'description': 'SQL injection attempt'
            },
            'xss': {
                'patterns': [
                    r'<script.*?>', r'javascript:', r'alert\(', 
                    r'onerror=', r'onload=', r'<iframe', r'document\.cookie',
                    r'window\.location', r'eval\s*\(', r'innerHTML\s*='
                ],
                'severity': 'high',
                'description': 'Cross-site scripting attempt'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./', r'\.\.\\', r'/etc/passwd', r'C:\\Windows\\',
                    r'/proc/self/', r'/bin/sh', r'/bin/bash'
                ],
                'severity': 'high',
                'description': 'Path traversal attempt'
            },
            'command_injection': {
                'patterns': [
                    r';.*ls', r'`.*`', r'\|\|.*', r'&&.*',
                    r'\$\(.*\)', r'\|.*sh', r'wget\s+http', r'curl\s+http'
                ],
                'severity': 'critical',
                'description': 'Command injection attempt'
            },
            'brute_force': {
                'patterns': [
                    r'Failed password', r'Invalid password', r'Authentication failure',
                    r'Login failed', r'Access denied', r'Invalid user'
                ],
                'severity': 'medium',
                'description': 'Brute force attack attempt'
            },
            'directory_enumeration': {
                'patterns': [
                    r'\.git/', r'\.env', r'wp-config\.php', r'\.DS_Store',
                    r'\.bak$', r'\.old$', r'\.sql$', r'\.tar\.gz$'
                ],
                'severity': 'low',
                'description': 'Directory/file enumeration'
            }
        }
    
    def parse_log_file(self, log_file):
        """Advanced log analysis with detailed reporting"""
        self.log(f"📝 Analyzing log file: {log_file}", "info")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            self.log(f"❌ Log file not found: {log_file}", "error")
            return {}
        except PermissionError:
            self.log(f"❌ Permission denied: {log_file}", "error")
            return {}
        
        findings = {
            'summary': {
                'total_lines': len(lines),
                'suspicious_activity': 0,
                'unique_ips': set(),
                'attacks_by_type': {},
                'timeline': []
            },
            'details': [],
            'top_attackers': {}
        }
        
        ip_counter = {}
        
        for line_num, line in enumerate(lines, 1):
            # Extract timestamp (common formats)
            timestamp = self._extract_timestamp(line)
            
            # Extract IP addresses
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            source_ip = ip_match.group(1) if ip_match else "Unknown"
            
            if source_ip != "Unknown":
                ip_counter[source_ip] = ip_counter.get(source_ip, 0) + 1
                findings['summary']['unique_ips'].add(source_ip)
            
            # Check for suspicious patterns
            for attack_type, attack_info in self.suspicious_patterns.items():
                for pattern in attack_info['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = {
                            'timestamp': timestamp,
                            'attack_type': attack_type,
                            'description': attack_info['description'],
                            'severity': attack_info['severity'],
                            'pattern': pattern,
                            'line_number': line_num,
                            'source_ip': source_ip,
                            'raw_line': line[:200]
                        }
                        
                        findings['details'].append(finding)
                        
                        findings['summary']['suspicious_activity'] += 1
                        findings['summary']['attacks_by_type'][attack_type] = \
                            findings['summary']['attacks_by_type'].get(attack_type, 0) + 1
                        
                        # Add to timeline
                        if timestamp:
                            findings['summary']['timeline'].append({
                                'timestamp': timestamp,
                                'attack_type': attack_type,
                                'severity': attack_info['severity'],
                                'source_ip': source_ip
                            })
                        
                        break
        
        # Calculate top attackers
        top_attackers = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        findings['top_attackers'] = dict(top_attackers)
        
        # Generate summary report
        self._generate_summary_report(findings)
        
        return findings
    
    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{10})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return None
    
    def _generate_summary_report(self, findings):
        """Generate comprehensive summary report"""
        summary = findings['summary']
        
        self.log(f"\n📊 LOG ANALYSIS SUMMARY", "info")
        self.log("=" * 60, "info")
        self.log(f"Total log entries: {summary['total_lines']:,}", "info")
        self.log(f"Unique IP addresses: {len(summary['unique_ips']):,}", "info")
        self.log(f"Suspicious activities detected: {summary['suspicious_activity']:,}", "info")
        
        if summary['suspicious_activity'] > 0:
            self.log(f"\n🔴 THREAT BREAKDOWN:", "info")
            for attack_type, count in sorted(summary['attacks_by_type'].items(), 
                                           key=lambda x: x[1], reverse=True):
                severity = self.suspicious_patterns.get(attack_type, {}).get('severity', 'unknown')
                severity_icon = "🟥" if severity == 'critical' else "🟧" if severity == 'high' else "🟨"
                self.log(f"  {severity_icon} {attack_type}: {count:,} incidents", "info")
        
        if findings['top_attackers']:
            self.log(f"\n🎯 TOP ATTACKERS:", "info")
            for ip, count in list(findings['top_attackers'].items())[:5]:
                self.log(f"  {ip}: {count:,} suspicious activities", "info")
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(summary['suspicious_activity'], 
                                                  len(summary['unique_ips']))
        self.log(f"\n⚠️ THREAT LEVEL: {threat_level}", 
                "error" if threat_level == "CRITICAL" else 
                "warning" if threat_level == "HIGH" else "info")
    
    def _calculate_threat_level(self, suspicious_count, unique_ips):
        """Calculate overall threat level"""
        if suspicious_count > 100 or unique_ips > 50:
            return "CRITICAL"
        elif suspicious_count > 50 or unique_ips > 20:
            return "HIGH"
        elif suspicious_count > 10 or unique_ips > 5:
            return "MEDIUM"
        elif suspicious_count > 0:
            return "LOW"
        else:
            return "CLEAN"


class ProfessionalPacketSniffer:
    """Professional packet sniffer with detailed protocol analysis"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.SCAPY_AVAILABLE = SCAPY_AVAILABLE
        self.is_sniffing = False
        self.captured_packets = []
        self.protocol_stats = {}
        self.sniffing_thread = None
        
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def start_sniffing(self, count=50, timeout=30, filter_exp=None):
        """Start professional packet capture"""
        if not self.SCAPY_AVAILABLE:
            self.log("❌ Scapy not available. Packet sniffing disabled.", "error")
            return []
        
        self.captured_packets.clear()
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.is_sniffing = True
        
        self.log(f"🎯 Starting professional packet capture...", "info")
        self.log(f"📊 Packets to capture: {count}", "info")
        self.log(f"⏱️ Timeout: {timeout} seconds", "info")
        self.log(f"🎯 BPF Filter: {filter_exp or 'None'}", "info")
        self.log(f"⚠️ Note: May require administrator/root privileges", "warning")
        self.log(f"\n{'='*60}\n", "info")
        
        packets = []
        
        def process_packet(packet):
            """Enhanced packet processing with detailed analysis"""
            packet_info = self._analyze_packet(packet)
            packets.append(packet_info)
            self.captured_packets.append(packet_info)
            
            # Update protocol statistics
            proto = packet_info.get('protocol', 'Other')
            self.protocol_stats[proto] = self.protocol_stats.get(proto, 0) + 1
            
            # Format output for display
            formatted_output = self._format_packet_display(packet_info, len(packets))
            if self.output_callback:
                self.output_callback(formatted_output, "info")
        
        try:
            sniff_kwargs = {
                'prn': process_packet,
                'count': count,
                'timeout': timeout,
                'store': False
            }
            
            if filter_exp and filter_exp.strip():
                sniff_kwargs['filter'] = filter_exp.strip()
            
            sniff(**sniff_kwargs)
            
        except Exception as e:
            self.log(f"❌ Error during packet capture: {str(e)}", "error")
            return []
        finally:
            self.is_sniffing = False
        
        self._generate_capture_summary()
        return packets
    
    def _analyze_packet(self, packet):
        """Deep packet analysis with multiple protocol layers"""
        packet_info = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'layers': [],
            'summary': packet.summary(),
            'raw_length': len(packet),
            'hex_preview': packet.hexdump()[:100] if hasattr(packet, 'hexdump') else ''
        }
        
        # Analyze each protocol layer
        layer = packet
        layer_count = 0
        
        while layer and layer_count < 5:
            layer_name = layer.name
            layer_info = self._extract_layer_info(layer)
            
            packet_info['layers'].append({
                'name': layer_name,
                'info': layer_info
            })
            
            # Move to next layer
            if hasattr(layer, 'payload'):
                layer = layer.payload
                layer_count += 1
            else:
                break
        
        # Extract common network information
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['ttl'] = ip_layer.ttl
            packet_info['protocol_num'] = ip_layer.proto
            
        if packet.haslayer('Ether'):
            eth_layer = packet['Ether']
            packet_info['src_mac'] = eth_layer.src
            packet_info['dst_mac'] = eth_layer.dst
        
        # Protocol-specific analysis
        if packet.haslayer('TCP'):
            packet_info['protocol'] = 'TCP'
            tcp_layer = packet['TCP']
            packet_info['src_port'] = tcp_layer.sport
            packet_info['dst_port'] = tcp_layer.dport
            packet_info['flags'] = self._decode_tcp_flags(tcp_layer.flags)
            packet_info['seq'] = tcp_layer.seq
            packet_info['ack'] = tcp_layer.ack
            
        elif packet.haslayer('UDP'):
            packet_info['protocol'] = 'UDP'
            udp_layer = packet['UDP']
            packet_info['src_port'] = udp_layer.sport
            packet_info['dst_port'] = udp_layer.dport
            packet_info['length'] = udp_layer.len
            
        elif packet.haslayer('ICMP'):
            packet_info['protocol'] = 'ICMP'
            icmp_layer = packet['ICMP']
            packet_info['type'] = icmp_layer.type
            packet_info['code'] = icmp_layer.code
            packet_info['icmp_type_desc'] = self._decode_icmp_type(icmp_layer.type)
            
        elif packet.haslayer('ARP'):
            packet_info['protocol'] = 'ARP'
            arp_layer = packet['ARP']
            packet_info['op'] = arp_layer.op
            packet_info['src_ip'] = arp_layer.psrc
            packet_info['dst_ip'] = arp_layer.pdst
            packet_info['src_mac'] = arp_layer.hwsrc
            packet_info['dst_mac'] = arp_layer.hwdst
            
        else:
            packet_info['protocol'] = f'Other-{packet_info.get("protocol_num", "Unknown")}'
        
        return packet_info
    
    def _extract_layer_info(self, layer):
        """Extract relevant information from a protocol layer"""
        info = {}
        
        if hasattr(layer, 'src'):
            info['src'] = layer.src
        if hasattr(layer, 'dst'):
            info['dst'] = layer.dst
        if hasattr(layer, 'sport'):
            info['sport'] = layer.sport
        if hasattr(layer, 'dport'):
            info['dport'] = layer.dport
        
        return info
    
    def _decode_tcp_flags(self, flags):
        """Decode TCP flags into human-readable format"""
        flag_names = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST',
            'P': 'PSH', 'A': 'ACK', 'U': 'URG',
            'E': 'ECE', 'C': 'CWR'
        }
        
        flag_str = str(flags)
        decoded = []
        
        for char in flag_str:
            if char in flag_names:
                decoded.append(flag_names[char])
        
        return ', '.join(decoded) if decoded else 'None'
    
    def _decode_icmp_type(self, type_code):
        """Decode ICMP type codes"""
        icmp_types = {
            0: 'Echo Reply', 3: 'Destination Unreachable',
            5: 'Redirect', 8: 'Echo Request',
            11: 'Time Exceeded', 30: 'Traceroute'
        }
        return icmp_types.get(type_code, f'Unknown ({type_code})')
    
    def _format_packet_display(self, packet_info, packet_num):
        """Create beautifully formatted packet display"""
        separator = "─" * 80
        output = f"\n{separator}\n"
        output += f"📦 PACKET #{packet_num:03d} "
        output += f"| Time: {packet_info['timestamp']} "
        output += f"| Length: {packet_info['raw_length']} bytes\n"
        output += f"{separator}\n"
        
        # Network information
        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
            src_port = packet_info.get('src_port', '')
            dst_port = packet_info.get('dst_port', '')
            src_port_str = f":{src_port}" if src_port else ""
            dst_port_str = f":{dst_port}" if dst_port else ""
            
            output += f"🌐 NETWORK: {packet_info['src_ip']}{src_port_str} → "
            output += f"{packet_info['dst_ip']}{dst_port_str}\n"
        
        if 'src_mac' in packet_info and 'dst_mac' in packet_info:
            output += f"🔗 MAC: {packet_info['src_mac'][:17]} → {packet_info['dst_mac'][:17]}\n"
        
        # Protocol information
        protocol = packet_info.get('protocol', 'Unknown')
        output += f"📡 PROTOCOL: {protocol}\n"
        
        # Protocol-specific details
        if protocol == 'TCP':
            flags = packet_info.get('flags', 'None')
            output += f"🚩 TCP FLAGS: {flags}\n"
            output += f"🔢 SEQ: {packet_info.get('seq', 'N/A')} | "
            output += f"ACK: {packet_info.get('ack', 'N/A')}\n"
            
        elif protocol == 'UDP':
            output += f"📏 UDP LENGTH: {packet_info.get('length', 'N/A')} bytes\n"
            
        elif protocol == 'ICMP':
            type_desc = packet_info.get('icmp_type_desc', 'Unknown')
            output += f"🎯 ICMP TYPE: {packet_info.get('type', 'N/A')} "
            output += f"({type_desc}) | CODE: {packet_info.get('code', 'N/A')}\n"
            
        elif protocol == 'ARP':
            op = packet_info.get('op', 'N/A')
            op_desc = "Request" if op == 1 else "Reply" if op == 2 else f"Unknown ({op})"
            output += f"🔍 ARP OPERATION: {op_desc} ({op})\n"
        
        # Layer information
        if packet_info['layers']:
            output += f"🔬 PROTOCOL LAYERS ({len(packet_info['layers'])}):\n"
            for i, layer in enumerate(packet_info['layers'], 1):
                layer_name = layer['name'].upper()
                layer_info = layer['info']
                info_str = ', '.join([f"{k}: {v}" for k, v in layer_info.items()])
                output += f"  {i}. {layer_name}"
                if info_str:
                    output += f" [{info_str}]"
                output += "\n"
        
        # Hex preview (truncated)
        if packet_info.get('hex_preview'):
            output += f"🔍 HEX PREVIEW: {packet_info['hex_preview'][:50]}...\n"
        
        # Packet summary
        output += f"📋 SUMMARY: {packet_info['summary'][:100]}\n"
        
        return output
    
    def _generate_capture_summary(self):
        """Generate comprehensive capture summary"""
        if not self.captured_packets:
            self.log("❌ No packets captured.", "error")
            return
        
        total_packets = len(self.captured_packets)
        total_size = sum(p['raw_length'] for p in self.captured_packets)
        
        self.log(f"\n{'='*60}", "info")
        self.log(f"📊 CAPTURE SUMMARY", "info")
        self.log(f"{'='*60}", "info")
        self.log(f"✅ Capture completed successfully!", "success")
        self.log(f"📦 Total packets captured: {total_packets:,}", "info")
        self.log(f"📏 Total data captured: {self._format_size(total_size)}", "info")
        
        self.log(f"\n📡 PROTOCOL DISTRIBUTION:", "info")
        for protocol, count in sorted(self.protocol_stats.items(), 
                                    key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / total_packets) * 100
                bar = "█" * int(percentage / 5)
                self.log(f"  {protocol:8} {count:6,} packets {percentage:6.1f}% {bar}", "info")
        
        # Show unique IPs
        src_ips = set(p.get('src_ip') for p in self.captured_packets if p.get('src_ip'))
        dst_ips = set(p.get('dst_ip') for p in self.captured_packets if p.get('dst_ip'))
        
        if src_ips:
            self.log(f"\n🎯 UNIQUE SOURCE IPs: {len(src_ips):,}", "info")
            if len(src_ips) <= 10:
                for ip in sorted(src_ips)[:10]:
                    self.log(f"  • {ip}", "info")
        
        if dst_ips:
            self.log(f"\n🎯 UNIQUE DESTINATION IPs: {len(dst_ips):,}", "info")
            if len(dst_ips) <= 10:
                for ip in sorted(dst_ips)[:10]:
                    self.log(f"  • {ip}", "info")
    
    def _format_size(self, size_bytes):
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def stop_sniffing(self):
        """Stop ongoing packet capture"""
        self.is_sniffing = False
        self.log("🛑 Packet capture stopped by user", "warning")


class EnhancedHTTPHeaderAuditor:
    """Professional HTTP security header auditor"""
    
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        if not REQUESTS_AVAILABLE:
            self.log("❌ HTTP auditor requires 'requests' library", "error")
        
        self.security_headers = {
            'Strict-Transport-Security': {
                'severity': 'critical',
                'description': 'Enforces HTTPS connections',
                'recommended': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'severity': 'critical',
                'description': 'Prevents XSS attacks',
                'recommended': "default-src 'self'"
            },
            'X-Frame-Options': {
                'severity': 'high',
                'description': 'Prevents clickjacking',
                'recommended': 'DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'severity': 'medium',
                'description': 'Prevents MIME sniffing',
                'recommended': 'nosniff'
            },
            'X-XSS-Protection': {
                'severity': 'medium',
                'description': 'Enables XSS filtering',
                'recommended': '1; mode=block'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Controls referrer information',
                'recommended': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'severity': 'medium',
                'description': 'Controls browser features',
                'recommended': 'Controls browser features'
            },
            'Cache-Control': {
                'severity': 'low',
                'description': 'Controls caching behavior',
                'recommended': 'no-store for sensitive data'
            }
        }
    
    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)
    
    def audit_url(self, url):
        """Comprehensive HTTP security audit"""
        if not REQUESTS_AVAILABLE:
            self.log("❌ Requests library not available", "error")
            return {}
        
        self.log(f"🔍 Auditing HTTP headers for: {url}", "info")
        self.log(f"{'='*60}", "info")
        
        try:
            # Make request with custom headers
            headers = {
                'User-Agent': 'SecurityToolkit-Auditor/1.0'
            }
            
            response = requests.get(url, timeout=15, allow_redirects=True, headers=headers)
            
            # Log basic response info
            self.log(f"✅ Connection successful", "success")
            self.log(f"📝 Final URL: {response.url}", "info")
            self.log(f"📊 Status Code: {response.status_code}", "info")
            self.log(f"🖥️ Server: {response.headers.get('Server', 'Not disclosed')}", "info")
            self.log(f"📏 Content Length: {len(response.content):,} bytes", "info")
            
            # Analyze headers
            headers = dict(response.headers)
            results = {
                'url': response.url,
                'status_code': response.status_code,
                'server': headers.get('Server'),
                'missing_headers': [],
                'weak_headers': [],
                'present_headers': [],
                'grade': 'A',
                'score': 100,
                'details': {}
            }
            
            self.log(f"\n🔐 SECURITY HEADER ANALYSIS:", "info")
            self.log(f"{'='*60}", "info")
            
            for header, header_info in self.security_headers.items():
                if header in headers:
                    header_value = headers[header]
                    results['present_headers'].append({
                        'name': header,
                        'value': header_value,
                        'severity': header_info['severity']
                    })
                    
                    # Check if header value is strong
                    is_strong = self._check_header_strength(header, header_value)
                    
                    if is_strong:
                        self.log(f"✅ {header}: {header_value[:50]}...", "success")
                    else:
                        results['weak_headers'].append({
                            'name': header,
                            'value': header_value,
                            'severity': header_info['severity']
                        })
                        self.log(f"⚠️ {header}: {header_value[:50]}... (Weak configuration)", "warning")
                        self.log(f"   Recommended: {header_info['recommended']}", "info")
                else:
                    results['missing_headers'].append({
                        'name': header,
                        'severity': header_info['severity']
                    })
                    self.log(f"❌ Missing: {header} ({header_info['description']})", "error")
                    self.log(f"   Recommended: {header_info['recommended']}", "info")
            
            # Calculate security score
            results = self._calculate_security_score(results)
            
            # Display grade
            grade_color = self._get_grade_color(results['grade'])
            self.log(f"\n{'='*60}", "info")
            self.log(f"📊 SECURITY ASSESSMENT", "info")
            self.log(f"{'='*60}", "info")
            self.log(f"🎓 SECURITY GRADE: {results['grade']}", grade_color)
            self.log(f"📈 SECURITY SCORE: {results['score']}/100", "info")
            self.log(f"✅ Headers present: {len(results['present_headers'])}", "info")
            self.log(f"⚠️ Weak headers: {len(results['weak_headers'])}", "warning")
            self.log(f"❌ Missing headers: {len(results['missing_headers'])}", "error")
            
            # Additional checks
            self._perform_additional_checks(response, results)
            
            return results
            
        except requests.RequestException as e:
            self.log(f"❌ Connection error: {str(e)}", "error")
            return {}
    
    def _check_header_strength(self, header, value):
        """Check if header value is strong"""
        value = value.lower()
        
        checks = {
            'Strict-Transport-Security': lambda v: 'max-age=' in v and int(v.split('max-age=')[1].split(';')[0]) >= 31536000,
            'X-Frame-Options': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': lambda v: 'nosniff' in v,
            'X-XSS-Protection': lambda v: '1; mode=block' in v,
            'Content-Security-Policy': lambda v: len(v) > 10,
            'Referrer-Policy': lambda v: 'strict' in v or 'origin' in v,
            'Permissions-Policy': lambda v: len(v) > 5,
            'Cache-Control': lambda v: 'no-store' in v or 'no-cache' in v or 'private' in v
        }
        
        if header in checks:
            return checks[header](value)
        
        return True
    
    def _calculate_security_score(self, results):
        """Calculate comprehensive security score"""
        score = 100
        deductions = 0
        
        # Deduct for missing headers
        for header in results['missing_headers']:
            severity = header['severity']
            if severity == 'critical':
                deductions += 20
            elif severity == 'high':
                deductions += 15
            elif severity == 'medium':
                deductions += 10
            else:
                deductions += 5
        
        # Deduct for weak headers
        for header in results['weak_headers']:
            severity = header['severity']
            if severity == 'critical':
                deductions += 10
            elif severity == 'high':
                deductions += 7
            elif severity == 'medium':
                deductions += 5
            else:
                deductions += 3
        
        score = max(0, score - deductions)
        
        # Determine grade
        if score >= 90:
            results['grade'] = 'A'
        elif score >= 80:
            results['grade'] = 'B'
        elif score >= 70:
            results['grade'] = 'C'
        elif score >= 60:
            results['grade'] = 'D'
        else:
            results['grade'] = 'F'
        
        results['score'] = score
        return results
    
    def _perform_additional_checks(self, response, results):
        """Perform additional security checks"""
        self.log(f"\n🔍 ADDITIONAL SECURITY CHECKS:", "info")
        self.log(f"{'='*60}", "info")
        
        # Check for HTTPS
        if response.url.startswith('https://'):
            self.log(f"✅ HTTPS Enabled (SSL/TLS)", "success")
            results['https_enabled'] = True
        else:
            self.log(f"❌ HTTPS Not Enabled (Using HTTP)", "error")
            results['https_enabled'] = False
        
        # Check cookies
        cookies = response.cookies
        if cookies:
            self.log(f"📦 Cookies detected: {len(cookies)}", "info")
            for cookie in cookies:
                secure_msg = "✅ Secure" if cookie.secure else "❌ Not Secure"
                http_only_msg = "✅ HttpOnly" if cookie.has_nonstandard_attr('httponly') else "❌ Not HttpOnly"
                self.log(f"  🍪 {cookie.name}: {secure_msg}, {http_only_msg}", "info")
        
        # Check response time
        if hasattr(response, 'elapsed'):
            response_time = response.elapsed.total_seconds() * 1000
            self.log(f"⏱️ Response Time: {response_time:.2f} ms", "info")
            results['response_time'] = response_time
    
    def _get_grade_color(self, grade):
        """Get color code for grade"""
        colors = {
            'A': 'success',
            'B': 'info',
            'C': 'warning',
            'D': 'error',
            'F': 'error'
        }
        return colors.get(grade, 'info')


# ============================================================================
# ENHANCED GUI APPLICATION WITH IMPROVED LAYOUT
# ============================================================================

class EnhancedSecurityToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Professional Security Automation Toolkit v2.0")
        self.root.geometry("1600x900")
        
        # Configure window
        self.root.state('zoomed')
        
        # Set icon if available
        try:
            self.root.iconbitmap('security_icon.ico')
        except:
            pass
        
        # Professional color scheme - fixed colors (no RGBA)
        self.colors = {
            'primary': "#1a237e",     # Dark blue
            'secondary': '#0d47a1',   # Blue
            'success': '#2e7d32',     # Green
            'danger': '#c62828',      # Red
            'warning': '#f57c00',     # Orange
            'info': '#0277bd',        # Light blue
            'light': '#f5f5f5',       # Light gray
            'dark': '#212121',        # Dark gray
            'accent': '#6a1b9a',      # Purple
            'background': '#ffffff',  # White
            'text': '#333333',        # Dark text
            'light_text': '#e0e0e0',  # Light text for dark backgrounds
            'highlight': '#bbdefb'    # Light blue highlight
        }
        
        # Configure styles
        self.setup_styles()
        
        # Main container with grid layout
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Setup GUI sections
        self.setup_header()
        self.setup_main_area()
        self.setup_status_bar()
        
        # Initialize enhanced tool classes
        self.initialize_enhanced_tools()
        
        # Statistics
        self.scan_stats = {
            'ports_scanned': 0,
            'files_hashed': 0,
            'packets_captured': 0,
            'threats_detected': 0,
            'vuln_scans': 0,
            'ssl_checks': 0
        }
        
        # Show dashboard initially
        self.show_dashboard()
    
    def setup_styles(self):
        """Configure professional styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=self.colors['background'])
        style.configure('TLabel', background=self.colors['background'], foreground=self.colors['text'])
        
        # Button styles
        style.configure('Primary.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       padding=8,
                       font=('Arial', 10, 'bold'),
                       borderwidth=1,
                       relief='raised')
        
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       padding=8,
                       font=('Arial', 10))
        
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       padding=8,
                       font=('Arial', 10))
        
        style.configure('Info.TButton',
                       background=self.colors['info'],
                       foreground='white',
                       padding=8,
                       font=('Arial', 10))
        
        # Notebook style
        style.configure('TNotebook', background=self.colors['light'])
        style.configure('TNotebook.Tab', 
                       background=self.colors['light'],
                       padding=[10, 5],
                       font=('Arial', 9))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['primary'])],
                 foreground=[('selected', 'white')])
        
        # Entry style
        style.configure('TEntry', padding=5)
        
        # Scrollbar style
        style.configure('Vertical.TScrollbar', 
                       background=self.colors['light'],
                       troughcolor=self.colors['background'],
                       bordercolor=self.colors['light'],
                       arrowcolor=self.colors['primary'])
        
        style.configure('Horizontal.TScrollbar',
                       background=self.colors['light'],
                       troughcolor=self.colors['background'],
                       bordercolor=self.colors['light'],
                       arrowcolor=self.colors['primary'])
    
    def setup_header(self):
        """Create professional header"""
        header_frame = tk.Frame(self.main_container, bg=self.colors['primary'], height=70)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)
        
        # Logo/Title
        title_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        title_frame.pack(side=tk.LEFT, padx=20)
        
        title = tk.Label(title_frame, 
                        text="🔒 SECURITY AUTOMATION TOOLKIT",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['primary'],
                        fg='white')
        title.pack()
        
        subtitle = tk.Label(title_frame,
                           text="Professional Security Assessment Platform",
                           font=('Arial', 10),
                           bg=self.colors['primary'],
                           fg=self.colors['light_text'])  # Fixed: Use light_text color instead of RGBA
        subtitle.pack()
        
        # Quick actions in header
        actions_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        actions_frame.pack(side=tk.RIGHT, padx=20)
        
        quick_actions = [
            ("💾 Save", self.save_log),
            ("📋 Copy", self.copy_to_clipboard),
            ("🧹 Clear", self.clear_output),
            ("🔄 Refresh", self.refresh_view)
        ]
        
        for text, command in quick_actions:
            btn = tk.Button(actions_frame, text=text, command=command,
                          bg=self.colors['secondary'],
                          fg='white',
                          font=('Arial', 9),
                          relief='flat',
                          padx=12,
                          pady=6,
                          cursor='hand2',
                          activebackground=self.colors['info'],
                          activeforeground='white')
            btn.pack(side=tk.LEFT, padx=3)
            
            # Add hover effect
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['info']))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=self.colors['secondary']))
    
    def setup_main_area(self):
        """Create main content area with navigation and workspace"""
        # Create paned window for resizable sections
        self.main_paned = ttk.PanedWindow(self.main_container, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Left navigation panel
        self.setup_navigation_panel()
        
        # Right workspace panel
        self.workspace_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(self.workspace_frame, weight=3)
        
        # Setup workspace
        self.setup_workspace()
    
    def setup_navigation_panel(self):
        """Create navigation panel"""
        nav_frame = tk.Frame(self.main_paned, bg=self.colors['light'], width=250)
        self.main_paned.add(nav_frame, weight=1)
        
        # Navigation container with scrollbar
        nav_container = tk.Frame(nav_frame, bg=self.colors['light'])
        nav_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar for navigation
        nav_canvas = tk.Canvas(nav_container, bg=self.colors['light'], highlightthickness=0)
        nav_scrollbar = ttk.Scrollbar(nav_container, orient=tk.VERTICAL, command=nav_canvas.yview)
        nav_scrollable_frame = tk.Frame(nav_canvas, bg=self.colors['light'])
        
        nav_scrollable_frame.bind(
            "<Configure>",
            lambda e: nav_canvas.configure(scrollregion=nav_canvas.bbox("all"))
        )
        
        nav_canvas.create_window((0, 0), window=nav_scrollable_frame, anchor="nw")
        nav_canvas.configure(yscrollcommand=nav_scrollbar.set)
        
        nav_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        nav_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Navigation title
        nav_title = tk.Label(nav_scrollable_frame,
                            text="NAVIGATION",
                            font=('Arial', 11, 'bold'),
                            bg=self.colors['primary'],
                            fg='white',
                            padx=15,
                            pady=10)
        nav_title.pack(fill=tk.X, pady=(0, 15))
        
        # Navigation buttons
        nav_categories = [
            ("📊 DASHBOARD", [
                ("📊 Overview", self.show_dashboard),
                ("📈 Statistics", self.show_statistics),
                ("📋 Reports", self.show_reports)
            ]),
            ("🔍 SCANNING TOOLS", [
                ("🔍 Port Scanner", self.show_port_scanner),
                ("🌐 Directory Scanner", self.show_directory_scanner),
                ("⚠️ Vulnerability Scanner", self.show_vuln_scanner)
            ]),
            ("🔐 SECURITY TOOLS", [
                ("🔐 File Integrity", self.show_file_checker),
                ("🔑 Password Checker", self.show_password_checker),
                ("🔐 SSL/TLS Checker", self.show_ssl_checker)
            ]),
            ("📡 NETWORK TOOLS", [
                ("📡 Packet Sniffer", self.show_packet_sniffer),
                ("📝 Log Analyzer", self.show_log_parser),
                ("🛡️ HTTP Auditor", self.show_http_auditor)
            ]),
            ("⚙️ SYSTEM", [
                ("⚙️ Settings", self.show_settings),
                ("🔄 Refresh All", self.refresh_all),
                ("🚪 Exit", self.root.quit)
            ])
        ]
        
        for category_title, buttons in nav_categories:
            # Category header
            category_frame = tk.Frame(nav_scrollable_frame, bg=self.colors['light'])
            category_frame.pack(fill=tk.X, pady=(15, 5))
            
            category_label = tk.Label(category_frame,
                                     text=category_title,
                                     font=('Arial', 10, 'bold'),
                                     bg=self.colors['light'],
                                     fg=self.colors['primary'],
                                     anchor=tk.W)
            category_label.pack(fill=tk.X, padx=10)
            
            # Category separator
            separator = ttk.Separator(category_frame, orient='horizontal')
            separator.pack(fill=tk.X, pady=5)
            
            # Category buttons
            for btn_text, command in buttons:
                btn = tk.Button(category_frame, text=btn_text, command=command,
                              bg=self.colors['light'],
                              fg=self.colors['text'],
                              font=('Arial', 9),
                              relief='flat',
                              anchor=tk.W,
                              padx=15,
                              pady=8,
                              cursor='hand2',
                              activebackground=self.colors['secondary'],
                              activeforeground='white')
                btn.pack(fill=tk.X, pady=1)
                
                # Hover effect
                btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['secondary'], fg='white'))
                btn.bind('<Leave>', lambda e, b=btn: 
                        b.config(bg=self.colors['light'], fg=self.colors['text']))
        
        # System status at bottom
        status_frame = tk.Frame(nav_scrollable_frame, bg=self.colors['light'])
        status_frame.pack(fill=tk.X, pady=20)
        
        status_title = tk.Label(status_frame,
                               text="SYSTEM STATUS",
                               font=('Arial', 10, 'bold'),
                               bg=self.colors['light'],
                               fg=self.colors['primary'])
        status_title.pack(anchor=tk.W, padx=10, pady=(0, 5))
        
        self.status_labels = {}
        status_items = [
            ("Python", f"✅ {sys.version.split()[0]}"),
            ("Requests", "✅ Available" if REQUESTS_AVAILABLE else "❌ Not Available"),
            ("Scapy", "✅ Available" if SCAPY_AVAILABLE else "❌ Not Available"),
            ("Network", "✅ Online"),
            ("Memory", "✓ Optimal")
        ]
        
        for name, status in status_items:
            frame = tk.Frame(status_frame, bg=self.colors['light'])
            frame.pack(fill=tk.X, pady=2)
            
            label = tk.Label(frame, text=name,
                           font=('Arial', 8),
                           bg=self.colors['light'],
                           fg=self.colors['text'],
                           width=10,
                           anchor=tk.W)
            label.pack(side=tk.LEFT, padx=10)
            
            status_color = self.colors['success'] if '✅' in status or '✓' in status else self.colors['danger']
            status_label = tk.Label(frame, text=status,
                                  font=('Arial', 8),
                                  bg=self.colors['light'],
                                  fg=status_color,
                                  anchor=tk.W)
            status_label.pack(side=tk.RIGHT, padx=10)
            self.status_labels[name] = status_label
    
    def setup_workspace(self):
        """Setup main workspace area"""
        # Create notebook for tabs
        self.workspace_notebook = ttk.Notebook(self.workspace_frame)
        self.workspace_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Console tab
        console_frame = ttk.Frame(self.workspace_notebook)
        self.workspace_notebook.add(console_frame, text="📝 Console Output")
        self.setup_console(console_frame)
        
        # Statistics tab
        stats_frame = ttk.Frame(self.workspace_notebook)
        self.workspace_notebook.add(stats_frame, text="📊 Statistics")
        self.setup_statistics(stats_frame)
        
        # Content frame (will be updated by navigation)
        self.content_frame = ttk.Frame(self.workspace_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
    
    def setup_console(self, parent):
        """Setup console output area"""
        # Main container with scrollbars
        console_container = tk.Frame(parent)
        console_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text widget with line numbers
        text_container = tk.Frame(console_container)
        text_container.pack(fill=tk.BOTH, expand=True)
        
        # Line numbers
        self.line_numbers = tk.Text(text_container,
                                   width=4,
                                   padx=5,
                                   pady=5,
                                   state='disabled',
                                   bg=self.colors['light'],
                                   fg=self.colors['text'],
                                   font=('Consolas', 10),
                                   wrap=tk.NONE)
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Console text widget
        self.output_text = tk.Text(text_container,
                                  wrap=tk.WORD,
                                  padx=10,
                                  pady=5,
                                  font=('Consolas', 10),
                                  bg='#1e1e1e',
                                  fg='#d4d4d4',
                                  insertbackground='white')
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(text_container, command=self.output_text.yview)
        h_scrollbar = ttk.Scrollbar(console_container, orient=tk.HORIZONTAL, command=self.output_text.xview)
        self.output_text.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Configure tags for colored output
        self.output_text.tag_config('info', foreground='#d4d4d4')
        self.output_text.tag_config('success', foreground='#4ec9b0')
        self.output_text.tag_config('error', foreground='#f44747')
        self.output_text.tag_config('warning', foreground='#dcdcaa')
        self.output_text.tag_config('header', foreground='#569cd6', font=('Consolas', 10, 'bold'))
        
        # Console controls
        controls_frame = tk.Frame(console_container, bg=self.colors['light'])
        controls_frame.pack(fill=tk.X, pady=(5, 0))
        
        controls = [
            ("🧹 Clear Console", self.clear_output),
            ("💾 Save Log", self.save_log),
            ("📋 Copy All", lambda: self.copy_to_clipboard()),
            ("🔍 Search", self.search_console)
        ]
        
        for text, command in controls:
            btn = tk.Button(controls_frame, text=text, command=command,
                          bg=self.colors['light'],
                          fg=self.colors['primary'],
                          font=('Arial', 8),
                          relief='flat',
                          padx=10,
                          pady=3,
                          cursor='hand2')
            btn.pack(side=tk.LEFT, padx=2)
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['secondary'], fg='white'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=self.colors['light'], fg=self.colors['primary']))
    
    def setup_statistics(self, parent):
        """Setup statistics display"""
        # Create scrollable statistics area
        stats_canvas = tk.Canvas(parent, bg=self.colors['background'], highlightthickness=0)
        stats_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=stats_canvas.yview)
        stats_scrollable_frame = tk.Frame(stats_canvas, bg=self.colors['background'])
        
        stats_scrollable_frame.bind(
            "<Configure>",
            lambda e: stats_canvas.configure(scrollregion=stats_canvas.bbox("all"))
        )
        
        stats_canvas.create_window((0, 0), window=stats_scrollable_frame, anchor="nw")
        stats_canvas.configure(yscrollcommand=stats_scrollbar.set)
        
        stats_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statistics title
        title = tk.Label(stats_scrollable_frame,
                        text="📊 SECURITY STATISTICS",
                        font=('Arial', 16, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=20)
        
        # Statistics cards
        cards_frame = tk.Frame(stats_scrollable_frame, bg=self.colors['background'])
        cards_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.stats_cards = {}
        
        stats_data = [
            ("🔍 Ports Scanned", "ports_scanned", "Network ports scanned successfully", self.colors['info']),
            ("🔐 Files Hashed", "files_hashed", "Files verified for integrity", self.colors['success']),
            ("📡 Packets Captured", "packets_captured", "Network packets analyzed", self.colors['accent']),
            ("⚠️ Threats Detected", "threats_detected", "Security threats identified", self.colors['danger']),
            ("🛡️ Vulnerability Scans", "vuln_scans", "Vulnerability assessments performed", self.colors['warning']),
            ("🔐 SSL/TLS Checks", "ssl_checks", "SSL certificates validated", self.colors['secondary'])
        ]
        
        for i, (title_text, key, description, color) in enumerate(stats_data):
            row = i // 3
            col = i % 3
            
            if col == 0:
                row_frame = tk.Frame(cards_frame, bg=self.colors['background'])
                row_frame.pack(fill=tk.X, pady=10)
            
            # Create card
            card = tk.Frame(row_frame, bg='white', relief=tk.RAISED, bd=1)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            # Card content
            content = tk.Frame(card, bg='white')
            content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            # Icon and title
            icon_label = tk.Label(content, text=title_text.split()[0],
                                font=('Arial', 24),
                                bg='white')
            icon_label.pack(pady=(0, 10))
            
            title_label = tk.Label(content, text=title_text.split()[1],
                                 font=('Arial', 12, 'bold'),
                                 bg='white',
                                 fg=color)
            title_label.pack(pady=(0, 5))
            
            # Value
            value_label = tk.Label(content, text="0",
                                 font=('Arial', 24, 'bold'),
                                 bg='white',
                                 fg=self.colors['dark'])
            value_label.pack(pady=(5, 10))
            
            # Description
            desc_label = tk.Label(content, text=description,
                                font=('Arial', 8),
                                bg='white',
                                fg=self.colors['text'],
                                wraplength=150,
                                justify=tk.CENTER)
            desc_label.pack()
            
            self.stats_cards[key] = value_label
        
        # Recent activity
        activity_frame = tk.LabelFrame(stats_scrollable_frame,
                                      text="📅 RECENT ACTIVITY",
                                      font=('Arial', 12, 'bold'),
                                      bg=self.colors['background'],
                                      fg=self.colors['primary'],
                                      padx=20,
                                      pady=20)
        activity_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.activity_list = tk.Text(activity_frame,
                                    height=8,
                                    font=('Arial', 9),
                                    bg=self.colors['light'],
                                    fg=self.colors['text'],
                                    wrap=tk.WORD)
        self.activity_list.pack(fill=tk.BOTH, expand=True)
        self.activity_list.insert(1.0, "No recent activity.\n")
        self.activity_list.config(state='disabled')
    
    def setup_status_bar(self):
        """Create professional status bar"""
        self.status_bar = tk.Frame(self.main_container, bg=self.colors['primary'], height=30)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar.pack_propagate(False)
        
        # Left side: status message
        self.status_label = tk.Label(self.status_bar,
                                    text="✅ System Ready",
                                    font=('Arial', 9),
                                    bg=self.colors['primary'],
                                    fg='white')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Progress bar area (initially empty)
        self.progress_frame = tk.Frame(self.status_bar, bg=self.colors['primary'])
        self.progress_frame.pack(side=tk.LEFT, padx=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame,
                                          variable=self.progress_var,
                                          length=200,
                                          mode='indeterminate')
        
        # Right side: time and date
        time_frame = tk.Frame(self.status_bar, bg=self.colors['primary'])
        time_frame.pack(side=tk.RIGHT, padx=10)
        
        self.date_label = tk.Label(time_frame,
                                  text="",
                                  font=('Arial', 9),
                                  bg=self.colors['primary'],
                                  fg='white')
        self.date_label.pack(side=tk.LEFT, padx=5)
        
        self.time_label = tk.Label(time_frame,
                                  text="",
                                  font=('Arial', 9, 'bold'),
                                  bg=self.colors['primary'],
                                  fg='white')
        self.time_label.pack(side=tk.LEFT, padx=5)
        
        self.update_time()
    
    def initialize_enhanced_tools(self):
        """Initialize enhanced tool classes"""
        self.tools = {
            'port_scanner': EnhancedPortScanner(self.log_output),
            'file_checker': EnhancedFileHashChecker(self.log_output),
            'directory_scanner': DirectoryBruteforcer(self.log_output),
            'log_parser': AdvancedLogParser(self.log_output),
            'packet_sniffer': ProfessionalPacketSniffer(self.log_output),
            'http_auditor': EnhancedHTTPHeaderAuditor(self.log_output),
            'vuln_scanner': BasicVulnerabilityScanner(self.log_output),
            'ssl_checker': SSLChecker(self.log_output),
            'password_checker': PasswordStrengthChecker(self.log_output)
        }
    
    def log_output(self, message, level="info"):
        """Enhanced log output with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        icons = {
            "success": "✅",
            "error": "❌",
            "warning": "⚠️",
            "info": "ℹ️"
        }
        
        prefix = icons.get(level, "📝")
        formatted = f"[{timestamp}] {prefix} {message}"
        
        self.output_text.insert(tk.END, formatted + "\n", level)
        self.output_text.see(tk.END)
        self._update_line_numbers()
        
        # Add to activity list
        self.activity_list.config(state='normal')
        if self.activity_list.get(1.0, tk.END).strip() == "No recent activity.":
            self.activity_list.delete(1.0, tk.END)
        self.activity_list.insert(tk.END, f"[{timestamp}] {message[:50]}...\n")
        self.activity_list.see(tk.END)
        self.activity_list.config(state='disabled')
        
        # Update status bar
        self.status_label.config(text=f"{prefix} {message[:40]}...")
    
    def _update_line_numbers(self, event=None):
        """Update line numbers"""
        self.line_numbers.config(state='normal')
        self.line_numbers.delete(1.0, tk.END)
        
        line_count = self.output_text.get(1.0, tk.END).count('\n')
        for i in range(1, line_count + 1):
            self.line_numbers.insert(tk.END, f"{i}\n")
        
        self.line_numbers.config(state='disabled')
    
    def update_time(self):
        """Update time in status bar"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        current_time = datetime.now().strftime("%H:%M:%S")
        
        self.date_label.config(text=current_date)
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_statistics(self, key, increment=1):
        """Update statistics"""
        if key in self.scan_stats:
            self.scan_stats[key] += increment
            if key in self.stats_cards:
                self.stats_cards[key].config(text=str(self.scan_stats[key]))
    
    def refresh_view(self):
        """Refresh current view"""
        current_tab = self.workspace_notebook.index(self.workspace_notebook.select())
        if current_tab == 0:  # Console
            self.output_text.see(tk.END)
        elif current_tab == 1:  # Statistics
            for key, label in self.stats_cards.items():
                label.config(text=str(self.scan_stats.get(key, 0)))
        self.log_output("🔄 View refreshed", "info")
    
    def refresh_all(self):
        """Refresh all components"""
        self.refresh_view()
        self.log_output("🔄 All components refreshed", "success")
    
    def search_console(self):
        """Search in console"""
        search_term = simpledialog.askstring("Search", "Enter search term:")
        if search_term:
            self.output_text.tag_remove('search', 1.0, tk.END)
            start_pos = '1.0'
            while True:
                start_pos = self.output_text.search(search_term, start_pos, tk.END, nocase=True)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(search_term)}c"
                self.output_text.tag_add('search', start_pos, end_pos)
                self.output_text.tag_config('search', background='yellow', foreground='black')
                start_pos = end_pos
    
    def clear_output(self):
        """Clear console output"""
        self.output_text.delete(1.0, tk.END)
        self._update_line_numbers()
        self.log_output("Console cleared", "info")
    
    def save_log(self):
        """Save log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"security_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.get(1.0, tk.END))
                self.log_output(f"Log saved to: {filename}", "success")
            except Exception as e:
                self.log_output(f"Error saving log: {str(e)}", "error")
    
    def copy_to_clipboard(self):
        """Copy to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))
        self.log_output("Output copied to clipboard", "success")
    
    # ============================================================================
    # VIEW FUNCTIONS WITH IMPROVED LAYOUT
    # ============================================================================
    
    def clear_content(self):
        """Clear content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        """Show enhanced dashboard"""
        self.clear_content()
        
        # Create scrollable dashboard
        dashboard_canvas = tk.Canvas(self.content_frame, bg=self.colors['background'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=dashboard_canvas.yview)
        scrollable_frame = tk.Frame(dashboard_canvas, bg=self.colors['background'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: dashboard_canvas.configure(scrollregion=dashboard_canvas.bbox("all"))
        )
        
        dashboard_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        dashboard_canvas.configure(yscrollcommand=scrollbar.set)
        
        dashboard_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Welcome section
        welcome_frame = tk.Frame(scrollable_frame, bg=self.colors['primary'])
        welcome_frame.pack(fill=tk.X, padx=20, pady=20)
        
        welcome_label = tk.Label(welcome_frame,
                                text="Welcome to Security Automation Toolkit",
                                font=('Arial', 24, 'bold'),
                                bg=self.colors['primary'],
                                fg='white',
                                pady=30)
        welcome_label.pack()
        
        subtitle_label = tk.Label(welcome_frame,
                                 text="Professional security assessment platform for penetration testers and security professionals",
                                 font=('Arial', 12),
                                 bg=self.colors['primary'],
                                 fg=self.colors['light_text'],
                                 wraplength=800)
        subtitle_label.pack(pady=(0, 30))
        
        # Tool grid
        tools_frame = tk.Frame(scrollable_frame, bg=self.colors['background'])
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        tools_grid = [
            ("🔍 Port Scanner", "Scan network ports and services", self.show_port_scanner, self.colors['info']),
            ("🔐 File Integrity", "Verify file hashes and integrity", self.show_file_checker, self.colors['success']),
            ("🌐 Directory Scanner", "Discover hidden web directories", self.show_directory_scanner, self.colors['warning']),
            ("📝 Log Analyzer", "Analyze logs for security threats", self.show_log_parser, self.colors['danger']),
            ("📡 Packet Sniffer", "Capture and analyze network traffic", self.show_packet_sniffer, self.colors['accent']),
            ("🛡️ HTTP Auditor", "Check web server security headers", self.show_http_auditor, self.colors['secondary']),
            ("⚠️ Vuln Scanner", "Scan for web vulnerabilities", self.show_vuln_scanner, self.colors['danger']),
            ("🔐 SSL Checker", "Validate SSL/TLS certificates", self.show_ssl_checker, self.colors['success']),
            ("🔑 Password Checker", "Analyze password strength", self.show_password_checker, self.colors['primary'])
        ]
        
        for i, (title, description, command, color) in enumerate(tools_grid):
            row = i // 3
            col = i % 3
            
            if col == 0:
                row_frame = tk.Frame(tools_frame, bg=self.colors['background'])
                row_frame.pack(fill=tk.X, pady=10)
            
            # Create tool card
            card = tk.Frame(row_frame, bg='white', relief=tk.RAISED, bd=1)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            # Card content
            content = tk.Frame(card, bg='white')
            content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            # Tool icon and title
            icon_label = tk.Label(content, text=title.split()[0],
                                font=('Arial', 32),
                                bg='white')
            icon_label.pack(pady=(0, 10))
            
            title_label = tk.Label(content, text=' '.join(title.split()[1:]),
                                 font=('Arial', 12, 'bold'),
                                 bg='white',
                                 fg=color)
            title_label.pack(pady=(0, 10))
            
            # Description
            desc_label = tk.Label(content, text=description,
                                font=('Arial', 9),
                                bg='white',
                                fg=self.colors['text'],
                                wraplength=200,
                                justify=tk.CENTER)
            desc_label.pack(pady=(0, 15))
            
            # Launch button
            launch_btn = tk.Button(content, text="Launch Tool", command=command,
                                  bg=color,
                                  fg='white',
                                  font=('Arial', 10, 'bold'),
                                  relief='flat',
                                  padx=20,
                                  pady=8,
                                  cursor='hand2')
            launch_btn.pack()
            
            # Hover effects
            def on_enter(e, c=card, b=launch_btn, col=color):
                c.config(bg='#f0f0f0')
                for child in c.winfo_children():
                    child.config(bg='#f0f0f0')
                b.config(bg=self.lighten_color(col, 20))
            
            def on_leave(e, c=card, b=launch_btn, col=color):
                c.config(bg='white')
                for child in c.winfo_children():
                    child.config(bg='white')
                b.config(bg=col)
            
            card.bind('<Enter>', on_enter)
            card.bind('<Leave>', on_leave)
    
    def show_file_checker(self):
        """Show enhanced file integrity checker"""
        self.clear_content()
        
        # Create scrollable frame
        main_canvas = tk.Canvas(self.content_frame, bg=self.colors['background'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        scrollable_frame = tk.Frame(main_canvas, bg=self.colors['background'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Title
        title = tk.Label(scrollable_frame,
                        text="🔐 File Integrity Checker",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=20)
        
        # Notebook for tabs
        notebook = ttk.Notebook(scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Single File Tab
        single_frame = ttk.Frame(notebook)
        notebook.add(single_frame, text="📄 Single File")
        
        # Create scrollable single file frame
        single_canvas = tk.Canvas(single_frame, bg=self.colors['background'], highlightthickness=0)
        single_scrollbar = ttk.Scrollbar(single_frame, orient=tk.VERTICAL, command=single_canvas.yview)
        single_scrollable = tk.Frame(single_canvas, bg=self.colors['background'])
        
        single_scrollable.bind(
            "<Configure>",
            lambda e: single_canvas.configure(scrollregion=single_canvas.bbox("all"))
        )
        
        single_canvas.create_window((0, 0), window=single_scrollable, anchor="nw")
        single_canvas.configure(yscrollcommand=single_scrollbar.set)
        
        single_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        single_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File selection section
        file_frame = tk.LabelFrame(single_scrollable,
                                  text="File Selection",
                                  font=('Arial', 12, 'bold'),
                                  bg=self.colors['background'],
                                  padx=20,
                                  pady=20)
        file_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(file_frame, text="Select a file to analyze:", 
                font=('Arial', 10),
                bg=self.colors['background']).pack(anchor=tk.W, pady=(0, 10))
        
        # File path input with browse button
        path_frame = tk.Frame(file_frame, bg=self.colors['background'])
        path_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_entry = tk.Entry(path_frame, font=('Arial', 10))
        self.file_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = tk.Button(path_frame, text="📁 Browse", command=self.browse_file,
                              bg=self.colors['secondary'],
                              fg='white',
                              font=('Arial', 10),
                              padx=15,
                              pady=5)
        browse_btn.pack(side=tk.RIGHT)
        
        # Algorithm selection
        algo_frame = tk.LabelFrame(single_scrollable,
                                  text="Hash Algorithm",
                                  font=('Arial', 12, 'bold'),
                                  bg=self.colors['background'],
                                  padx=20,
                                  pady=20)
        algo_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.algorithm_var = tk.StringVar(value="sha256")
        
        algorithms = [
            ("MD5", "md5", "Fast but cryptographically broken"),
            ("SHA-1", "sha1", "More secure than MD5"),
            ("SHA-256", "sha256", "Recommended (Secure)"),
            ("SHA-512", "sha512", "Most secure, slower"),
            ("SHA3-256", "sha3_256", "Next-generation secure")
        ]
        
        for i, (name, value, description) in enumerate(algorithms):
            frame = tk.Frame(algo_frame, bg=self.colors['background'])
            frame.pack(fill=tk.X, pady=5)
            
            rb = tk.Radiobutton(frame, text=name, variable=self.algorithm_var, value=value,
                               bg=self.colors['background'],
                               font=('Arial', 10))
            rb.pack(side=tk.LEFT)
            
            desc_label = tk.Label(frame, text=description,
                                 font=('Arial', 8),
                                 bg=self.colors['background'],
                                 fg=self.colors['text'])
            desc_label.pack(side=tk.LEFT, padx=20)
        
        # Expected hash (for verification)
        hash_frame = tk.LabelFrame(single_scrollable,
                                  text="Verification (Optional)",
                                  font=('Arial', 12, 'bold'),
                                  bg=self.colors['background'],
                                  padx=20,
                                  pady=20)
        hash_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(hash_frame, text="Expected Hash (for verification):",
                font=('Arial', 10),
                bg=self.colors['background']).pack(anchor=tk.W, pady=(0, 10))
        
        self.expected_hash_entry = tk.Text(hash_frame, height=3, font=('Consolas', 9))
        self.expected_hash_entry.pack(fill=tk.X, pady=5)
        
        # Action buttons
        btn_frame = tk.Frame(single_scrollable, bg=self.colors['background'])
        btn_frame.pack(pady=30)
        
        tk.Button(btn_frame, text="🔍 Calculate Hash", 
                 command=self.calculate_single_hash,
                 bg=self.colors['info'],
                 fg='white',
                 font=('Arial', 11, 'bold'),
                 padx=20,
                 pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="✅ Verify File", 
                 command=self.verify_single_file,
                 bg=self.colors['success'],
                 fg='white',
                 font=('Arial', 11, 'bold'),
                 padx=20,
                 pady=10).pack(side=tk.LEFT, padx=10)
        
        # Directory Baseline Tab
        dir_frame = ttk.Frame(notebook)
        notebook.add(dir_frame, text="📁 Directory Baseline")
        
        # Create scrollable directory frame
        dir_canvas = tk.Canvas(dir_frame, bg=self.colors['background'], highlightthickness=0)
        dir_scrollbar = ttk.Scrollbar(dir_frame, orient=tk.VERTICAL, command=dir_canvas.yview)
        dir_scrollable = tk.Frame(dir_canvas, bg=self.colors['background'])
        
        dir_scrollable.bind(
            "<Configure>",
            lambda e: dir_canvas.configure(scrollregion=dir_canvas.bbox("all"))
        )
        
        dir_canvas.create_window((0, 0), window=dir_scrollable, anchor="nw")
        dir_canvas.configure(yscrollcommand=dir_scrollbar.set)
        
        dir_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dir_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Directory selection
        dir_select_frame = tk.LabelFrame(dir_scrollable,
                                        text="Directory Selection",
                                        font=('Arial', 12, 'bold'),
                                        bg=self.colors['background'],
                                        padx=20,
                                        pady=20)
        dir_select_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(dir_select_frame, text="Select a directory to create baseline:",
                font=('Arial', 10),
                bg=self.colors['background']).pack(anchor=tk.W, pady=(0, 10))
        
        dir_path_frame = tk.Frame(dir_select_frame, bg=self.colors['background'])
        dir_path_frame.pack(fill=tk.X, pady=5)
        
        self.dir_path_entry = tk.Entry(dir_path_frame, font=('Arial', 10))
        self.dir_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(dir_path_frame, text="📁 Browse", command=self.browse_directory,
                 bg=self.colors['secondary'],
                 fg='white',
                 font=('Arial', 10),
                 padx=15,
                 pady=5).pack(side=tk.RIGHT)
        
        # Baseline options
        baseline_frame = tk.LabelFrame(dir_scrollable,
                                      text="Baseline Options",
                                      font=('Arial', 12, 'bold'),
                                      bg=self.colors['background'],
                                      padx=20,
                                      pady=20)
        baseline_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(baseline_frame, text="Algorithm:",
                font=('Arial', 10),
                bg=self.colors['background']).grid(row=0, column=0, sticky=tk.W, pady=10)
        
        self.baseline_algo = ttk.Combobox(baseline_frame, 
                                         values=['sha256', 'sha512', 'md5', 'sha1'],
                                         state='readonly',
                                         font=('Arial', 10))
        self.baseline_algo.set('sha256')
        self.baseline_algo.grid(row=0, column=1, padx=20, pady=10, sticky=tk.W)
        
        # Create baseline button
        baseline_btn_frame = tk.Frame(dir_scrollable, bg=self.colors['background'])
        baseline_btn_frame.pack(pady=30)
        
        tk.Button(baseline_btn_frame, text="📊 Create Baseline", 
                 command=self.create_baseline,
                 bg=self.colors['primary'],
                 fg='white',
                 font=('Arial', 12, 'bold'),
                 padx=30,
                 pady=12).pack()
    
    def show_port_scanner(self):
        """Show enhanced port scanner interface"""
        self.clear_content()
        
        # Create scrollable frame
        main_canvas = tk.Canvas(self.content_frame, bg=self.colors['background'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        scrollable_frame = tk.Frame(main_canvas, bg=self.colors['background'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Title
        title = tk.Label(scrollable_frame,
                        text="🔍 Port Scanner",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=20)
        
        # Configuration section
        config_frame = tk.LabelFrame(scrollable_frame,
                                    text="Scan Configuration",
                                    font=('Arial', 12, 'bold'),
                                    bg=self.colors['background'],
                                    padx=20,
                                    pady=20)
        config_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Target input
        tk.Label(config_frame, text="Target Host/IP:",
                font=('Arial', 10),
                bg=self.colors['background']).grid(row=0, column=0, sticky=tk.W, pady=10)
        
        self.target_entry = tk.Entry(config_frame, font=('Arial', 10), width=40)
        self.target_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        self.target_entry.insert(0, "127.0.0.1")
        
        # Port range
        tk.Label(config_frame, text="Port Range:",
                font=('Arial', 10),
                bg=self.colors['background']).grid(row=1, column=0, sticky=tk.W, pady=10)
        
        self.port_range_entry = tk.Entry(config_frame, font=('Arial', 10), width=40)
        self.port_range_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)
        self.port_range_entry.insert(0, "1-1024")
        
        # Quick port ranges
        quick_frame = tk.Frame(config_frame, bg=self.colors['background'])
        quick_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        quick_ranges = {
            "Common (1-1000)": "1-1000",
            "Standard (1-1024)": "1-1024",
            "All (1-65535)": "1-65535",
            "Web (80,443,8080)": "80,443,8080,8443"
        }
        
        for text, ports in quick_ranges.items():
            btn = tk.Button(quick_frame, text=text,
                          command=lambda p=ports: self.port_range_entry.delete(0, tk.END) or self.port_range_entry.insert(0, p),
                          bg=self.colors['light'],
                          fg=self.colors['primary'],
                          font=('Arial', 8),
                          padx=10,
                          pady=3)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Advanced options
        adv_frame = tk.LabelFrame(config_frame,
                                 text="Advanced Options",
                                 font=('Arial', 11, 'bold'),
                                 bg=self.colors['background'],
                                 padx=20,
                                 pady=15)
        adv_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W+tk.E, pady=20, padx=5)
        
        # Threads
        tk.Label(adv_frame, text="Threads:",
                font=('Arial', 10),
                bg=self.colors['background']).grid(row=0, column=0, sticky=tk.W, pady=10)
        
        self.threads_var = tk.IntVar(value=100)
        threads_scale = tk.Scale(adv_frame, from_=10, to=500,
                                variable=self.threads_var,
                                orient=tk.HORIZONTAL,
                                length=200,
                                bg=self.colors['background'],
                                font=('Arial', 9))
        threads_scale.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Timeout
        tk.Label(adv_frame, text="Timeout (s):",
                font=('Arial', 10),
                bg=self.colors['background']).grid(row=0, column=2, sticky=tk.W, pady=10, padx=(20,0))
        
        self.timeout_var = tk.IntVar(value=2)
        timeout_spin = tk.Spinbox(adv_frame, from_=1, to=30,
                                 textvariable=self.timeout_var,
                                 width=10,
                                 font=('Arial', 10))
        timeout_spin.grid(row=0, column=3, padx=10, pady=10, sticky=tk.W)
        
        # Results section
        results_frame = tk.LabelFrame(scrollable_frame,
                                     text="Scan Results",
                                     font=('Arial', 12, 'bold'),
                                     bg=self.colors['background'],
                                     padx=20,
                                     pady=20)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Results treeview
        columns = ('Port', 'Service', 'Status', 'Banner')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)
        
        # Add scrollbars to treeview
        tree_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control buttons
        btn_frame = tk.Frame(scrollable_frame, bg=self.colors['background'])
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="🚀 Start Scan", 
                 command=self.start_port_scan,
                 bg=self.colors['success'],
                 fg='white',
                 font=('Arial', 12, 'bold'),
                 padx=30,
                 pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="🧹 Clear Results",
                 command=self.clear_results,
                 bg=self.colors['warning'],
                 fg='white',
                 font=('Arial', 12),
                 padx=20,
                 pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="💾 Export Results",
                 command=self.export_results,
                 bg=self.colors['info'],
                 fg='white',
                 font=('Arial', 12),
                 padx=20,
                 pady=10).pack(side=tk.LEFT, padx=10)
    
    def show_directory_scanner(self):
        """Show directory scanner interface"""
        self.show_tool_placeholder("🌐 Directory Scanner", "directory_scanner")
    
    def show_log_parser(self):
        """Show log parser interface"""
        self.show_tool_placeholder("📝 Log Analyzer", "log_parser")
    
    def show_packet_sniffer(self):
        """Show packet sniffer interface"""
        self.show_tool_placeholder("📡 Packet Sniffer", "packet_sniffer")
    
    def show_http_auditor(self):
        """Show HTTP auditor interface"""
        self.show_tool_placeholder("🛡️ HTTP Auditor", "http_auditor")
    
    def show_vuln_scanner(self):
        """Show vulnerability scanner interface"""
        self.show_tool_placeholder("⚠️ Vulnerability Scanner", "vuln_scanner")
    
    def show_ssl_checker(self):
        """Show SSL checker interface"""
        self.show_tool_placeholder("🔐 SSL/TLS Checker", "ssl_checker")
    
    def show_password_checker(self):
        """Show password checker interface"""
        self.show_tool_placeholder("🔑 Password Checker", "password_checker")
    
    def show_statistics(self):
        """Show statistics view"""
        self.workspace_notebook.select(1)  # Select statistics tab
    
    def show_reports(self):
        """Show reports view"""
        self.clear_content()
        title = tk.Label(self.content_frame,
                        text="📈 Reports & Analytics",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=50)
        
        info = tk.Label(self.content_frame,
                       text="Advanced reporting features coming in v3.0",
                       font=('Arial', 12),
                       bg=self.colors['background'],
                       fg=self.colors['text'])
        info.pack()
    
    def show_settings(self):
        """Show settings view"""
        self.clear_content()
        title = tk.Label(self.content_frame,
                        text="⚙️ Settings & Configuration",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=50)
        
        info = tk.Label(self.content_frame,
                       text="Settings panel coming in v3.0",
                       font=('Arial', 12),
                       bg=self.colors['background'],
                       fg=self.colors['text'])
        info.pack()
    
    def show_tool_placeholder(self, tool_name, tool_key):
        """Show tool placeholder"""
        self.clear_content()
        
        title = tk.Label(self.content_frame,
                        text=tool_name,
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['background'],
                        fg=self.colors['primary'])
        title.pack(pady=50)
        
        info = tk.Label(self.content_frame,
                       text=f"{tool_name} interface coming in next update",
                       font=('Arial', 12),
                       bg=self.colors['background'],
                       fg=self.colors['text'])
        info.pack()
        
        # Add a simple demo button if the tool exists
        if hasattr(self, 'tools') and tool_key in self.tools:
            test_btn = tk.Button(self.content_frame, text=f"Test {tool_name}",
                               command=lambda: self.test_tool(tool_key),
                               bg=self.colors['secondary'],
                               fg='white',
                               font=('Arial', 12),
                               padx=20,
                               pady=10)
            test_btn.pack(pady=20)
    
    def test_tool(self, tool_key):
        """Test a tool functionality"""
        if tool_key == 'port_scanner':
            self.log_output(f"Testing {tool_key}...", "info")
            self.tools[tool_key].scan_port("127.0.0.1", 80)
        elif tool_key == 'file_checker':
            self.log_output(f"Testing {tool_key}...", "info")
            # Test with a dummy file
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
                f.write("test content")
                temp_file = f.name
            self.tools[tool_key].calculate_hash(temp_file, 'md5')
            os.unlink(temp_file)
        else:
            self.log_output(f"{tool_key} test not implemented", "warning")
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def lighten_color(self, color, amount):
        """Lighten a color by specified amount"""
        try:
            from colorsys import rgb_to_hls, hls_to_rgb
            import re
            
            hex_color = color.lstrip('#')
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            h, l, s = rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
            l = min(1, l + amount/100)
            
            rgb = tuple(int(x*255) for x in hls_to_rgb(h, l, s))
            return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'
        except:
            return color
    
    def browse_file(self):
        """Browse for a file"""
        filename = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All files", "*.*")]
        )
        
        if filename and hasattr(self, 'file_path_entry'):
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, filename)
            self.log_output(f"Selected file: {filename}", "info")
    
    def browse_directory(self):
        """Browse for a directory"""
        directory = filedialog.askdirectory(title="Select Directory")
        if directory and hasattr(self, 'dir_path_entry'):
            self.dir_path_entry.delete(0, tk.END)
            self.dir_path_entry.insert(0, directory)
            self.log_output(f"Selected directory: {directory}", "info")
    
    # ============================================================================
    # TOOL ACTION METHODS
    # ============================================================================
    
    def start_port_scan(self):
        """Start port scan"""
        target = self.target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        # Show progress
        self.progress_bar.pack(in_=self.progress_frame, padx=10)
        self.progress_bar.start()
        self.status_label.config(text="🔄 Scanning ports...")
        
        def scan_thread():
            try:
                open_ports = self.tools['port_scanner'].threaded_scan(
                    target, port_range, int(self.threads_var.get()))
                
                # Clear and update results
                self.results_tree.delete(*self.results_tree.get_children())
                for port, service, banner in sorted(open_ports, key=lambda x: x[0]):
                    banner_preview = banner[:50] + "..." if banner and len(banner) > 50 else banner or ""
                    self.results_tree.insert('', tk.END, values=(port, service, "Open", banner_preview))
                
                self.update_statistics('ports_scanned', len(open_ports))
                self.log_output(f"Port scan completed. Found {len(open_ports)} open ports.", "success")
                
            except Exception as e:
                self.log_output(f"Scan error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def calculate_single_hash(self):
        """Calculate hash for single file"""
        file_path = self.file_path_entry.get().strip()
        algorithm = self.algorithm_var.get()
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        self.progress_bar.pack(in_=self.progress_frame, padx=10)
        self.progress_bar.start()
        self.status_label.config(text="🔄 Calculating hash...")
        
        def calculate_thread():
            try:
                hash_value = self.tools['file_checker'].calculate_hash(file_path, algorithm)
                if hash_value:
                    self.expected_hash_entry.delete(1.0, tk.END)
                    self.expected_hash_entry.insert(1.0, hash_value)
                    self.update_statistics('files_hashed', 1)
                    self.log_output(f"Hash calculated: {hash_value[:32]}...", "success")
            except Exception as e:
                self.log_output(f"Error calculating hash: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=calculate_thread, daemon=True).start()
    
    def verify_single_file(self):
        """Verify file integrity"""
        file_path = self.file_path_entry.get().strip()
        algorithm = self.algorithm_var.get()
        expected_hash = self.expected_hash_entry.get(1.0, tk.END).strip()
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        self.progress_bar.pack(in_=self.progress_frame, padx=10)
        self.progress_bar.start()
        self.status_label.config(text="🔄 Verifying file...")
        
        def verify_thread():
            try:
                result = self.tools['file_checker'].verify_file(file_path, expected_hash or None, algorithm)
                if result:
                    self.update_statistics('files_hashed', 1)
                    self.log_output("File integrity verified", "success")
                else:
                    self.log_output("File integrity check failed", "error")
            except Exception as e:
                self.log_output(f"Verification error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=verify_thread, daemon=True).start()
    
    def create_baseline(self):
        """Create directory baseline"""
        directory = self.dir_path_entry.get().strip()
        algorithm = self.baseline_algo.get()
        
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory")
            return
        
        self.progress_bar.pack(in_=self.progress_frame, padx=10)
        self.progress_bar.start()
        self.status_label.config(text="🔄 Creating baseline...")
        
        def baseline_thread():
            try:
                baseline_file = self.tools['file_checker'].create_directory_baseline(directory, algorithm)
                if baseline_file:
                    self.log_output(f"Baseline created: {baseline_file}", "success")
            except Exception as e:
                self.log_output(f"Baseline creation error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=baseline_thread, daemon=True).start()
    
    def clear_results(self):
        """Clear scan results"""
        if hasattr(self, 'results_tree'):
            self.results_tree.delete(*self.results_tree.get_children())
        self.log_output("Results cleared", "info")
    
    def export_results(self):
        """Export results"""
        if not hasattr(self, 'results_tree') or not self.results_tree.get_children():
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Port,Service,Status,Banner\n")
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        f.write(f"{values[0]},{values[1]},{values[2]},{values[3]}\n")
                self.log_output(f"Results exported to: {filename}", "success")
            except Exception as e:
                self.log_output(f"Export error: {str(e)}", "error")


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Set window properties
    root.title("Security Automation Toolkit")
    root.geometry("1400x800")
    
    try:
        # Try to set icon (if exists)
        root.iconbitmap('security.ico')
    except:
        pass
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Create application
    app = EnhancedSecurityToolkitGUI(root)
    
    # Start main loop
    root.mainloop()


if __name__ == "__main__":
    main()