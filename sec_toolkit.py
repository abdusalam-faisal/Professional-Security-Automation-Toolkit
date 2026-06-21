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
# ENHANCED CORE TOOL CLASSES
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
# ENHANCED GUI APPLICATION WITH SCROLLBARS
# ============================================================================

class EnhancedSecurityToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Professional Security Automation Toolkit")
        self.root.geometry("1400x900")
        
        # Set window state to maximized
        self.root.state('zoomed')
        
        # Icon (if available)
        try:
            self.root.iconbitmap('security_icon.ico')
        except:
            pass
        
        # Configure styles
        self.setup_styles()
        
        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Setup GUI
        self.setup_sidebar()
        self.setup_main_area()
        self.setup_status_bar()
        
        # Initialize enhanced tool classes
        self.initialize_enhanced_tools()
        
        # Statistics
        self.scan_stats = {
            'ports_scanned': 0,
            'files_hashed': 0,
            'packets_captured': 0,
            'threats_detected': 0
        }
    
    def setup_styles(self):
        """Configure professional styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Professional color scheme
        self.colors = {
            'primary': "#2c3e50",
            'secondary': '#3498db',
            'success': '#27ae60',
            'danger': '#e74c3c',
            'warning': '#f39c12',
            'info': '#3498db',
            'light': '#ecf0f1',
            'dark': '#2c3e50',
            'accent': '#9b59b6'
        }
        
        # Configure button styles
        style.configure('Primary.TButton', 
                       background=self.colors['primary'],
                       foreground='white',
                       padding=10,
                       font=('Arial', 10, 'bold'))
        
        style.configure('Success.TButton', 
                       background=self.colors['success'],
                       foreground='white',
                       padding=10)
        
        style.configure('Danger.TButton', 
                       background=self.colors['danger'],
                       foreground='white',
                       padding=10)
        
        style.configure('Info.TButton', 
                       background=self.colors['info'],
                       foreground='white',
                       padding=10)
        
        # Configure treeview
        style.configure("Treeview", 
                       background='white',
                       foreground=self.colors['dark'],
                       rowheight=25,
                       fieldbackground='white',
                       font=('Consolas', 9))
        
        style.configure("Treeview.Heading",
                       background=self.colors['primary'],
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        
        style.map('Treeview', 
                 background=[('selected', self.colors['secondary'])],
                 foreground=[('selected', 'white')])
        
        # Configure labels
        style.configure('Title.TLabel',
                       font=('Arial', 16, 'bold'),
                       foreground=self.colors['primary'])
        
        style.configure('Subtitle.TLabel',
                       font=('Arial', 12, 'bold'),
                       foreground=self.colors['secondary'])
    
    def setup_sidebar(self):
        """Create professional sidebar navigation"""
        sidebar = ttk.Frame(self.main_container, width=220)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Logo/Title
        title_frame = ttk.Frame(sidebar)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title = tk.Label(title_frame, text="🔒 SECURITY TOOLKIT", 
                        font=('Arial', 18, 'bold'),
                        foreground=self.colors['primary'],
                        bg=self.colors['light'],
                        padx=20,
                        pady=15)
        title.pack(fill=tk.X)
        
        # Version info
        version = tk.Label(title_frame, text="v2.0 Professional",
                          font=('Arial', 9),
                          foreground=self.colors['info'])
        version.pack(pady=(0, 10))
        
        # Navigation buttons with icons
        nav_buttons = [
            ("📊 Dashboard", self.show_dashboard),
            ("🔍 Port Scanner", self.show_port_scanner),
            ("🔐 File Integrity", self.show_file_checker),
            ("🌐 Directory Scanner", self.show_directory_scanner),
            ("📝 Log Analyzer", self.show_log_parser),
            ("📡 Packet Sniffer", self.show_packet_sniffer),
            ("🛡️ HTTP Auditor", self.show_http_auditor),
            ("⚠️ Vuln Scanner", self.show_vuln_scanner),
            ("🔐 SSL Checker", self.show_ssl_checker),
            ("🔑 Password Check", self.show_password_checker),
            ("📈 Reports", self.show_reports),
            ("⚙️ Settings", self.show_settings)
        ]
        
        for text, command in nav_buttons:
            btn_frame = ttk.Frame(sidebar)
            btn_frame.pack(fill=tk.X, pady=1, padx=5)
            
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg=self.colors['light'],
                          fg=self.colors['primary'],
                          font=('Arial', 11),
                          relief=tk.FLAT,
                          anchor=tk.W,
                          padx=15,
                          pady=10,
                          cursor='hand2')
            btn.pack(fill=tk.X)
            
            # Add hover effect
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['secondary'], fg='white'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=self.colors['light'], fg=self.colors['primary']))
        
        # System status panel
        status_frame = ttk.LabelFrame(sidebar, text="System Status", padding=15)
        status_frame.pack(fill=tk.X, pady=20, padx=5)
        
        self.status_labels = {}
        status_items = [
            ("Python", f"✅ {sys.version.split()[0]}"),
            ("Requests", "✅ Available" if REQUESTS_AVAILABLE else "❌ Not Available"),
            ("Scapy", "✅ Available" if SCAPY_AVAILABLE else "❌ Not Available"),
            ("Threads", "✅ Ready"),
            ("Network", "✅ Online")
        ]
        
        for name, status in status_items:
            frame = ttk.Frame(status_frame)
            frame.pack(fill=tk.X, pady=2)
            
            icon = "🟢" if "✅" in status else "🔴" if "❌" in status else "🟡"
            label = tk.Label(frame, text=f"{icon} {name}:", 
                           font=('Arial', 9, 'bold'),
                           anchor=tk.W)
            label.pack(side=tk.LEFT)
            
            status_text = status.replace("✅", "").replace("❌", "").strip()
            status_label = tk.Label(frame, text=status_text,
                                  font=('Arial', 9),
                                  anchor=tk.W)
            status_label.pack(side=tk.RIGHT)
            self.status_labels[name] = status_label
        
        # Exit button
        exit_frame = ttk.Frame(sidebar)
        exit_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10, padx=5)
        
        exit_btn = tk.Button(exit_frame, text="🚪 Exit Toolkit", 
                           command=self.root.quit,
                           bg=self.colors['danger'],
                           fg='white',
                           font=('Arial', 11, 'bold'),
                           relief=tk.RAISED,
                           padx=20,
                           pady=12,
                           cursor='hand2')
        exit_btn.pack(fill=tk.X)
    
    def setup_main_area(self):
        """Create professional main content area"""
        self.main_area = ttk.Frame(self.main_container)
        self.main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Header with breadcrumb
        self.header_frame = ttk.Frame(self.main_area, height=60)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        self.header_frame.pack_propagate(False)
        
        # Title label
        self.title_label = tk.Label(self.header_frame, text="Dashboard",
                                   font=('Arial', 20, 'bold'),
                                   foreground=self.colors['primary'],
                                   bg='white',
                                   padx=20)
        self.title_label.pack(side=tk.LEFT)
        
        # Quick actions
        quick_frame = ttk.Frame(self.header_frame)
        quick_frame.pack(side=tk.RIGHT, padx=20)
        
        quick_buttons = [
            ("💾 Save", self.save_log),
            ("📋 Copy", self.copy_to_clipboard),
            ("🧹 Clear", self.clear_output)
        ]
        
        for text, command in quick_buttons:
            btn = ttk.Button(quick_frame, text=text, command=command,
                           style='Info.TButton',
                           width=8)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Content area
        self.content_frame = ttk.Frame(self.main_area)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output console with tabs
        output_notebook = ttk.Notebook(self.main_area)
        output_notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Console tab
        console_frame = ttk.Frame(output_notebook)
        output_notebook.add(console_frame, text="📝 Console Output")
        
        # Create text widget with line numbers
        text_container = ttk.Frame(console_frame)
        text_container.pack(fill=tk.BOTH, expand=True)
        
        # Line numbers
        self.line_numbers = tk.Text(text_container, 
                                   width=4,
                                   padx=5,
                                   pady=5,
                                   state='disabled',
                                   bg=self.colors['light'],
                                   fg=self.colors['dark'],
                                   font=('Consolas', 10))
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Text widget
        self.output_text = tk.Text(text_container,
                                  wrap=tk.WORD,
                                  padx=10,
                                  pady=5,
                                  font=('Consolas', 10),
                                  bg='#1e1e1e',
                                  fg='#d4d4d4',
                                  insertbackground='white')
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(text_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure scrolling
        self.output_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.output_text.yview)
        
        # Link line numbers
        self.output_text.bind('<KeyRelease>', self._update_line_numbers)
        self.output_text.bind('<MouseWheel>', self._update_line_numbers)
        self.output_text.bind('<Button-1>', self._update_line_numbers)
        
        # Configure tags for colored output
        tags_config = {
            'info': {'foreground': '#d4d4d4'},
            'success': {'foreground': '#4ec9b0'},
            'error': {'foreground': '#f44747'},
            'warning': {'foreground': '#dcdcaa'},
            'header': {'foreground': '#569cd6', 'font': ('Consolas', 10, 'bold')},
            'highlight': {'background': '#264f78'}
        }
        
        for tag, config in tags_config.items():
            self.output_text.tag_config(tag, **config)
        
        # Stats tab
        stats_frame = ttk.Frame(output_notebook)
        output_notebook.add(stats_frame, text="📊 Statistics")
        
        # Create scrollable frame for statistics
        stats_canvas = tk.Canvas(stats_frame, bg='white')
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=stats_canvas.yview)
        stats_scrollable_frame = ttk.Frame(stats_canvas)
        
        stats_scrollable_frame.bind(
            "<Configure>",
            lambda e: stats_canvas.configure(scrollregion=stats_canvas.bbox("all"))
        )
        
        stats_canvas.create_window((0, 0), window=stats_scrollable_frame, anchor="nw")
        stats_canvas.configure(yscrollcommand=stats_scrollbar.set)
        
        stats_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statistics display
        stats_grid = ttk.Frame(stats_scrollable_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.stats_labels = {}
        stats_items = [
            ("Ports Scanned", "ports_scanned", "🔍"),
            ("Files Hashed", "files_hashed", "🔐"),
            ("Packets Captured", "packets_captured", "📡"),
            ("Threats Detected", "threats_detected", "⚠️")
        ]
        
        for i, (title, key, icon) in enumerate(stats_items):
            frame = tk.Frame(stats_grid, bg=self.colors['light'], relief=tk.RAISED, bd=1)
            frame.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="nsew")
            stats_grid.grid_rowconfigure(i//2, weight=1)
            stats_grid.grid_columnconfigure(i%2, weight=1)
            
            # Icon and title
            icon_label = tk.Label(frame, text=icon, font=('Arial', 24), 
                                bg=self.colors['light'])
            icon_label.pack(pady=(10, 5))
            
            title_label = tk.Label(frame, text=title, font=('Arial', 10),
                                 bg=self.colors['light'])
            title_label.pack()
            
            # Value
            value_label = tk.Label(frame, text="0", font=('Arial', 24, 'bold'),
                                 bg=self.colors['light'],
                                 fg=self.colors['primary'])
            value_label.pack(pady=(5, 10))
            
            self.stats_labels[key] = value_label
    
    def setup_status_bar(self):
        """Create professional status bar"""
        self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, height=25)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status message
        self.status_label = ttk.Label(self.status_bar, text="✅ Ready")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Progress bar (hidden by default)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.status_bar, 
                                          variable=self.progress_var,
                                          length=200,
                                          mode='indeterminate')
        
        # Time and date
        time_frame = ttk.Frame(self.status_bar)
        time_frame.pack(side=tk.RIGHT, padx=10)
        
        self.date_label = ttk.Label(time_frame, text="")
        self.date_label.pack(side=tk.LEFT, padx=5)
        
        self.time_label = ttk.Label(time_frame, text="", font=('Arial', 9, 'bold'))
        self.time_label.pack(side=tk.LEFT)
        
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
        
        # Load initial view
        self.show_dashboard()
    
    def log_output(self, message, level="info"):
        """Enhanced log output with timestamp and formatting"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Format message based on level
        if level == "success":
            prefix = "✅"
        elif level == "error":
            prefix = "❌"
        elif level == "warning":
            prefix = "⚠️"
        elif level == "info":
            prefix = "ℹ️"
        else:
            prefix = "📝"
        
        formatted_message = f"[{timestamp}] {prefix} {message}"
        
        # Insert with appropriate tag
        self.output_text.insert(tk.END, formatted_message + "\n", level)
        self.output_text.see(tk.END)
        
        # Update line numbers
        self._update_line_numbers()
        
        # Update status bar for important messages
        if level in ["error", "warning"]:
            self.status_label.config(text=f"{prefix} {message[:50]}...")
    
    def _update_line_numbers(self, event=None):
        """Update line numbers in the console"""
        # Store current view
        current_scroll = self.output_text.yview()
        
        # Update line numbers
        self.line_numbers.config(state='normal')
        self.line_numbers.delete(1.0, tk.END)
        
        line_count = self.output_text.get(1.0, tk.END).count('\n')
        for i in range(1, line_count + 1):
            self.line_numbers.insert(tk.END, f"{i:4}\n")
        
        self.line_numbers.config(state='disabled')
        
        # Restore view
        self.output_text.yview_moveto(current_scroll[0])
        self.line_numbers.yview_moveto(current_scroll[0])
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
        self._update_line_numbers()
        self.log_output("Console cleared", "info")
    
    def save_log(self):
        """Save log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
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
        """Copy log to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))
        self.log_output("Output copied to clipboard", "success")
    
    def update_time(self):
        """Update time in status bar"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        current_time = datetime.now().strftime("%H:%M:%S")
        
        self.date_label.config(text=current_date)
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_statistics(self, key, increment=1):
        """Update statistics counter"""
        if key in self.scan_stats:
            self.scan_stats[key] += increment
            if key in self.stats_labels:
                self.stats_labels[key].config(text=str(self.scan_stats[key]))
    
    # ============================================================================
    # VIEW FUNCTIONS WITH SCROLLBARS
    # ============================================================================
    
    def clear_content(self):
        """Clear content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        """Show enhanced dashboard view"""
        self.clear_content()
        self.title_label.config(text="📊 Security Dashboard")
        
        # Create scrollable dashboard
        dashboard_canvas = tk.Canvas(self.content_frame, bg='white')
        dashboard_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=dashboard_canvas.yview)
        dashboard_scrollable_frame = ttk.Frame(dashboard_canvas)
        
        dashboard_scrollable_frame.bind(
            "<Configure>",
            lambda e: dashboard_canvas.configure(scrollregion=dashboard_canvas.bbox("all"))
        )
        
        dashboard_canvas.create_window((0, 0), window=dashboard_scrollable_frame, anchor="nw")
        dashboard_canvas.configure(yscrollcommand=dashboard_scrollbar.set)
        
        dashboard_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dashboard_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Welcome header
        welcome_frame = tk.Frame(dashboard_scrollable_frame, bg=self.colors['primary'])
        welcome_frame.pack(fill=tk.X, padx=20, pady=10)
        
        welcome_label = tk.Label(welcome_frame, 
                                text="Welcome to Professional Security Toolkit",
                                font=('Arial', 16, 'bold'),
                                fg='white',
                                bg=self.colors['primary'],
                                pady=20)
        welcome_label.pack()
        
        # Tool cards grid
        cards_frame = ttk.Frame(dashboard_scrollable_frame)
        cards_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Professional tool cards
        cards = [
            ("🔍 Port Scanner", "Scan network ports and detect services", 
             self.colors['secondary'], self.show_port_scanner, "network"),
            ("🔐 File Integrity", "Verify file hashes and monitor changes", 
             self.colors['success'], self.show_file_checker, "security"),
            ("🌐 Directory Scanner", "Discover hidden web directories", 
             self.colors['warning'], self.show_directory_scanner, "web"),
            ("📝 Log Analyzer", "Analyze logs for security threats", 
             self.colors['info'], self.show_log_parser, "analysis"),
            ("📡 Packet Sniffer", "Capture and analyze network traffic", 
             self.colors['danger'], self.show_packet_sniffer, "network"),
            ("🛡️ HTTP Auditor", "Check web server security headers", 
             self.colors['accent'], self.show_http_auditor, "web")
        ]
        
        # Create 3x2 grid
        row, col = 0, 0
        for title, description, color, command, category in cards:
            card = tk.Frame(cards_frame, bg='white', relief=tk.RAISED, bd=2)
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            card.grid_rowconfigure(0, weight=1)
            card.grid_columnconfigure(0, weight=1)
            
            # Make cells expand equally
            cards_frame.grid_rowconfigure(row, weight=1)
            cards_frame.grid_columnconfigure(col, weight=1)
            
            # Category badge
            badge = tk.Label(card, text=category.upper(),
                           font=('Arial', 8, 'bold'),
                           bg=color,
                           fg='white',
                           padx=5,
                           pady=2)
            badge.place(x=10, y=10)
            
            # Card content
            content_frame = tk.Frame(card, bg='white')
            content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=30)
            
            # Icon
            icon_label = tk.Label(content_frame, text=title.split()[0],
                                font=('Arial', 32),
                                bg='white')
            icon_label.pack()
            
            # Title
            title_words = title.split()
            title_text = ' '.join(title_words[1:]) if len(title_words) > 1 else title
            title_label = tk.Label(content_frame, text=title_text,
                                 font=('Arial', 14, 'bold'),
                                 bg='white',
                                 fg=self.colors['dark'])
            title_label.pack(pady=(10, 5))
            
            # Description
            desc_label = tk.Label(content_frame, text=description,
                                font=('Arial', 10),
                                bg='white',
                                fg='#666',
                                wraplength=180,
                                justify=tk.CENTER)
            desc_label.pack(pady=5)
            
            # Action button
            action_btn = tk.Button(content_frame, text="Launch Tool",
                                  command=command,
                                  bg=color,
                                  fg='white',
                                  font=('Arial', 10, 'bold'),
                                  relief=tk.FLAT,
                                  padx=20,
                                  pady=8,
                                  cursor='hand2')
            action_btn.pack(pady=(15, 10))
            
            # Hover effects
            def on_enter(e, c=card, b=action_btn, col=color):
                c.config(bg='#f8f9fa')
                content_frame.config(bg='#f8f9fa')
                title_label.config(bg='#f8f9fa')
                desc_label.config(bg='#f8f9fa')
                b.config(bg=self._lighten_color(col, 20))
            
            def on_leave(e, c=card, b=action_btn, col=color):
                c.config(bg='white')
                content_frame.config(bg='white')
                title_label.config(bg='white')
                desc_label.config(bg='white')
                b.config(bg=col)
            
            card.bind('<Enter>', on_enter)
            card.bind('<Leave>', on_leave)
            action_btn.bind('<Enter>', lambda e, b=action_btn, col=color: 
                          b.config(bg=self._lighten_color(col, 20)))
            action_btn.bind('<Leave>', lambda e, b=action_btn, col=color: 
                          b.config(bg=col))
            
            col += 1
            if col >= 2:
                col = 0
                row += 1
        
        # Quick actions panel
        actions_frame = ttk.LabelFrame(dashboard_scrollable_frame, text="⚡ Quick Actions", padding=20)
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        action_buttons = [
            ("🔍 Quick Port Scan", self.quick_scan_localhost),
            ("🔐 Check System Files", self.check_system_files),
            ("📡 Quick Network Capture", self.quick_network_capture),
            ("📊 Generate Report", self.generate_report)
        ]
        
        for text, command in action_buttons:
            btn = ttk.Button(actions_frame, text=text, command=command,
                           style='Primary.TButton')
            btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    def _lighten_color(self, color, amount):
        """Lighten a color by specified amount"""
        try:
            from colorsys import rgb_to_hls, hls_to_rgb
            import re
            
            # Convert hex to rgb
            hex_color = color.lstrip('#')
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            # Convert to hls
            h, l, s = rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
            
            # Increase lightness
            l = min(1, l + amount/100)
            
            # Convert back to rgb
            rgb = tuple(int(x*255) for x in hls_to_rgb(h, l, s))
            
            # Convert back to hex
            return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'
        except:
            return color
    
    def show_port_scanner(self):
        """Show enhanced port scanner interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🔍 Port Scanner")
        
        # Create main container with scrollbars
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Main container with tabs
        notebook = ttk.Notebook(main_scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scan configuration tab
        config_frame = ttk.Frame(notebook)
        notebook.add(config_frame, text="⚙️ Configuration")
        
        # Create scrollable config frame
        config_canvas = tk.Canvas(config_frame, bg='white')
        config_scrollbar = ttk.Scrollbar(config_frame, orient=tk.VERTICAL, command=config_canvas.yview)
        config_scrollable_frame = ttk.Frame(config_canvas)
        
        config_scrollable_frame.bind(
            "<Configure>",
            lambda e: config_canvas.configure(scrollregion=config_canvas.bbox("all"))
        )
        
        config_canvas.create_window((0, 0), window=config_scrollable_frame, anchor="nw")
        config_canvas.configure(yscrollcommand=config_scrollbar.set)
        
        config_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        config_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Input frame
        input_frame = ttk.LabelFrame(config_scrollable_frame, text="Scan Parameters", padding=20)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Target input
        target_frame = ttk.Frame(input_frame)
        target_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(target_frame, text="Target:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(target_frame, width=40, font=('Arial', 10))
        self.target_entry.pack(side=tk.LEFT, padx=10)
        self.target_entry.insert(0, "127.0.0.1")
        
        # Quick targets
        quick_targets = ["localhost", "127.0.0.1", "192.168.1.1", "google.com"]
        quick_frame = ttk.Frame(target_frame)
        quick_frame.pack(side=tk.LEFT, padx=10)
        
        for target in quick_targets:
            btn = ttk.Button(quick_frame, text=target, 
                           command=lambda t=target: self.target_entry.delete(0, tk.END) or self.target_entry.insert(0, t),
                           width=10)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Port range
        range_frame = ttk.Frame(input_frame)
        range_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(range_frame, text="Port Range:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        self.port_range_entry = ttk.Entry(range_frame, width=20, font=('Arial', 10))
        self.port_range_entry.pack(side=tk.LEFT, padx=10)
        self.port_range_entry.insert(0, "1-1024")
        
        # Common port ranges
        common_frame = ttk.Frame(range_frame)
        common_frame.pack(side=tk.LEFT, padx=10)
        
        common_ranges = {
            "Quick (1-100)": "1-100",
            "Standard (1-1024)": "1-1024",
            "All (1-65535)": "1-65535",
            "Web (80,443,8080)": "80,443,8080,8443"
        }
        
        for name, ports in common_ranges.items():
            btn = ttk.Button(common_frame, text=name,
                           command=lambda p=ports: self.port_range_entry.delete(0, tk.END) or self.port_range_entry.insert(0, p),
                           width=15)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Advanced options
        adv_frame = ttk.LabelFrame(input_frame, text="Advanced Options", padding=10)
        adv_frame.pack(fill=tk.X, pady=10)
        
        # Threads
        ttk.Label(adv_frame, text="Threads:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.IntVar(value=100)
        threads_scale = ttk.Scale(adv_frame, from_=10, to=500, 
                                 variable=self.threads_var, length=200)
        threads_scale.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        threads_label = ttk.Label(adv_frame, textvariable=self.threads_var)
        threads_label.grid(row=0, column=2, padx=5)
        
        # Timeout
        ttk.Label(adv_frame, text="Timeout (s):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.IntVar(value=2)
        timeout_spin = ttk.Spinbox(adv_frame, from_=1, to=30, 
                                  textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Control buttons
        button_frame = ttk.Frame(config_scrollable_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="🚀 Start Scan", 
                  command=self.start_port_scan,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💾 Export Results", 
                  command=self.export_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 Copy Results", 
                  command=self.copy_scan_results).pack(side=tk.LEFT, padx=5)
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="📊 Results")
        
        # Create scrollable results frame
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Results treeview
        columns = ('Port', 'Service', 'Status', 'Banner')
        self.results_tree = ttk.Treeview(results_scrollable_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        column_widths = {'Port': 80, 'Service': 150, 'Status': 100, 'Banner': 300}
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=column_widths.get(col, 100))
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(results_scrollable_frame, orient=tk.VERTICAL, 
                                   command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_scrollable_frame, orient=tk.HORIZONTAL,
                                   command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set,
                                  xscrollcommand=h_scrollbar.set)
        
        # Layout
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        results_scrollable_frame.grid_rowconfigure(0, weight=1)
        results_scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # Summary frame
        summary_frame = ttk.LabelFrame(results_scrollable_frame, text="Scan Summary", padding=10)
        summary_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        
        self.summary_labels = {
            'total': ttk.Label(summary_frame, text="Total: 0"),
            'open': ttk.Label(summary_frame, text="Open: 0"),
            'closed': ttk.Label(summary_frame, text="Closed: 0"),
            'duration': ttk.Label(summary_frame, text="Duration: 0s")
        }
        
        for i, (key, label) in enumerate(self.summary_labels.items()):
            label.grid(row=0, column=i, padx=20)
    
    def show_file_checker(self):
        """Show enhanced file integrity checker with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🔐 File Integrity Checker")
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        notebook = ttk.Notebook(main_scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Single File Tab
        single_frame = ttk.Frame(notebook)
        notebook.add(single_frame, text="📄 Single File")
        
        # Create scrollable single file frame
        single_canvas = tk.Canvas(single_frame, bg='white')
        single_scrollbar = ttk.Scrollbar(single_frame, orient=tk.VERTICAL, command=single_canvas.yview)
        single_scrollable_frame = ttk.Frame(single_canvas)
        
        single_scrollable_frame.bind(
            "<Configure>",
            lambda e: single_canvas.configure(scrollregion=single_canvas.bbox("all"))
        )
        
        single_canvas.create_window((0, 0), window=single_scrollable_frame, anchor="nw")
        single_canvas.configure(yscrollcommand=single_scrollbar.set)
        
        single_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        single_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File selection
        file_frame = ttk.LabelFrame(single_scrollable_frame, text="File Selection", padding=20)
        file_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(file_frame, text="File Path:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=5)
        
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_entry = ttk.Entry(path_frame, width=60)
        self.file_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(path_frame, text="📁 Browse", 
                  command=self.browse_file).pack(side=tk.RIGHT, padx=2)
        ttk.Button(path_frame, text="📋 Paste Path", 
                  command=self.paste_from_clipboard).pack(side=tk.RIGHT, padx=2)
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(single_scrollable_frame, text="Hash Algorithm", padding=15)
        algo_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.algorithm_var = tk.StringVar(value="sha256")
        
        algo_grid = ttk.Frame(algo_frame)
        algo_grid.pack()
        
        algorithms = [
            ("MD5", "md5", "Fast but cryptographically broken"),
            ("SHA-1", "sha1", "More secure than MD5"),
            ("SHA-256", "sha256", "Recommended (Secure)"),
            ("SHA-512", "sha512", "Most secure, slower"),
            ("SHA3-256", "sha3_256", "Next-generation secure")
        ]
        
        for i, (name, value, description) in enumerate(algorithms):
            rb = ttk.Radiobutton(algo_grid, text=name, variable=self.algorithm_var, value=value)
            rb.grid(row=i, column=0, sticky=tk.W, pady=2)
            
            desc_label = ttk.Label(algo_grid, text=description, font=('Arial', 8), foreground='#666')
            desc_label.grid(row=i, column=1, sticky=tk.W, padx=10, pady=2)
        
        # Expected hash
        hash_frame = ttk.LabelFrame(single_scrollable_frame, text="Verification (Optional)", padding=15)
        hash_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(hash_frame, text="Expected Hash:").pack(anchor=tk.W, pady=2)
        
        hash_text_frame = tk.Frame(hash_frame)
        hash_text_frame.pack(fill=tk.X, pady=5)
        
        self.expected_hash_entry = tk.Text(hash_text_frame, height=3, width=60)
        scrollbar = ttk.Scrollbar(hash_text_frame, orient=tk.VERTICAL, command=self.expected_hash_entry.yview)
        self.expected_hash_entry.configure(yscrollcommand=scrollbar.set)
        
        self.expected_hash_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button
        btn_frame = ttk.Frame(single_scrollable_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="🔍 Calculate Hash", 
                  command=self.calculate_single_hash,
                  style='Info.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="✅ Verify File", 
                  command=self.verify_single_file,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
        # Directory Baseline Tab
        dir_frame = ttk.Frame(notebook)
        notebook.add(dir_frame, text="📁 Directory Baseline")
        
        # Create scrollable directory frame
        dir_canvas = tk.Canvas(dir_frame, bg='white')
        dir_scrollbar = ttk.Scrollbar(dir_frame, orient=tk.VERTICAL, command=dir_canvas.yview)
        dir_scrollable_frame = ttk.Frame(dir_canvas)
        
        dir_scrollable_frame.bind(
            "<Configure>",
            lambda e: dir_canvas.configure(scrollregion=dir_canvas.bbox("all"))
        )
        
        dir_canvas.create_window((0, 0), window=dir_scrollable_frame, anchor="nw")
        dir_canvas.configure(yscrollcommand=dir_scrollbar.set)
        
        dir_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dir_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Directory selection
        dir_select_frame = ttk.LabelFrame(dir_scrollable_frame, text="Directory Selection", padding=20)
        dir_select_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(dir_select_frame, text="Directory Path:").pack(anchor=tk.W, pady=5)
        
        dir_path_frame = ttk.Frame(dir_select_frame)
        dir_path_frame.pack(fill=tk.X, pady=5)
        
        self.dir_path_entry = ttk.Entry(dir_path_frame, width=60)
        self.dir_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(dir_path_frame, text="📁 Browse", 
                  command=self.browse_directory).pack(side=tk.RIGHT, padx=2)
        
        # Baseline options
        baseline_frame = ttk.LabelFrame(dir_scrollable_frame, text="Baseline Options", padding=15)
        baseline_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(baseline_frame, text="Baseline Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.baseline_name = ttk.Entry(baseline_frame, width=40)
        self.baseline_name.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        ttk.Label(baseline_frame, text="Algorithm:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.baseline_algo = ttk.Combobox(baseline_frame, values=['sha256', 'sha512', 'md5', 'sha1'])
        self.baseline_algo.set('sha256')
        self.baseline_algo.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Create baseline button
        baseline_btn_frame = ttk.Frame(dir_scrollable_frame)
        baseline_btn_frame.pack(pady=20)
        
        ttk.Button(baseline_btn_frame, text="📊 Create Baseline", 
                  command=self.create_baseline,
                  style='Primary.TButton').pack()
    
    def show_directory_scanner(self):
        """Show directory scanner interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🌐 Directory Scanner")
        
        if not REQUESTS_AVAILABLE:
            self.show_dependency_warning("requests", "Directory Scanner")
            return
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configuration
        config_frame = ttk.LabelFrame(main_scrollable_frame, text="Configuration", padding=20)
        config_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        # URL input
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.url_entry.insert(0, "http://localhost")
        
        # Quick URLs
        url_frame = ttk.Frame(config_frame)
        url_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        quick_urls = ["http://localhost", "http://127.0.0.1", "https://example.com"]
        for url in quick_urls:
            btn = ttk.Button(url_frame, text=url, width=15,
                           command=lambda u=url: self.url_entry.delete(0, tk.END) or self.url_entry.insert(0, u))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Wordlist selection
        ttk.Label(config_frame, text="Wordlist:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        wordlist_frame = ttk.Frame(config_frame)
        wordlist_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        self.wordlist_var = tk.StringVar(value="Built-in")
        wordlist_combo = ttk.Combobox(wordlist_frame, textvariable=self.wordlist_var, 
                                     values=["Built-in", "Custom..."], width=15)
        wordlist_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(wordlist_frame, text="📁 Load Custom",
                  command=self.load_custom_wordlist).pack(side=tk.LEFT)
        
        # Threads
        ttk.Label(config_frame, text="Threads:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.dir_threads = ttk.Scale(config_frame, from_=1, to=50, length=200, orient=tk.HORIZONTAL)
        self.dir_threads.set(10)
        self.dir_threads.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_scrollable_frame, text="Discovered Resources", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Create scrollable results area
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Results treeview
        columns = ('URL', 'Status', 'Size', 'Title')
        self.dir_results_tree = ttk.Treeview(results_scrollable_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.dir_results_tree.heading(col, text=col)
            self.dir_results_tree.column(col, width=150)
        
        # Scrollbars for treeview
        v_scroll = ttk.Scrollbar(results_scrollable_frame, orient=tk.VERTICAL, command=self.dir_results_tree.yview)
        h_scroll = ttk.Scrollbar(results_scrollable_frame, orient=tk.HORIZONTAL, command=self.dir_results_tree.xview)
        self.dir_results_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Layout
        self.dir_results_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        results_scrollable_frame.grid_rowconfigure(0, weight=1)
        results_scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # Button frame - IMPORTANT: This was missing!
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        # Add visible buttons with proper styling
        start_btn = ttk.Button(button_frame, text="🚀 Start Scan", 
                              command=self.start_directory_scan,
                              style='Success.TButton',
                              width=15)
        start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        clear_btn = ttk.Button(button_frame, text="🧹 Clear Results", 
                              command=lambda: self.dir_results_tree.delete(*self.dir_results_tree.get_children()),
                              width=15)
        clear_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        export_btn = ttk.Button(button_frame, text="💾 Export Results", 
                               command=self.export_dir_results,
                               width=15)
        export_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    def show_log_parser(self):
        """Show enhanced log parser interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="📝 Log Analyzer")
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File selection
        file_frame = ttk.LabelFrame(main_scrollable_frame, text="Log File", padding=15)
        file_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        ttk.Label(file_frame, text="Log File Path:").pack(anchor=tk.W, pady=5)
        
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.log_file_entry = ttk.Entry(path_frame)
        self.log_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(path_frame, text="📁 Browse", 
                  command=lambda: self.browse_file(self.log_file_entry)).pack(side=tk.RIGHT, padx=2)
        ttk.Button(path_frame, text="📋 Paste", 
                  command=lambda: self.log_file_entry.insert(0, self.root.clipboard_get())).pack(side=tk.RIGHT, padx=2)
        
        # Common log files
        common_frame = ttk.Frame(file_frame)
        common_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(common_frame, text="Common locations:").pack(side=tk.LEFT)
        
        common_logs = [
            ("Apache", "/var/log/apache2/access.log"),
            ("Nginx", "/var/log/nginx/access.log"),
            ("SSH", "/var/log/auth.log"),
            ("System", "/var/log/syslog")
        ]
        
        for name, path in common_logs:
            btn = ttk.Button(common_frame, text=name, width=10,
                           command=lambda p=path: self.log_file_entry.delete(0, tk.END) or self.log_file_entry.insert(0, p))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Analysis tabs
        notebook = ttk.Notebook(main_scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Statistics tab
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Statistics")
        
        # Create scrollable statistics frame
        stats_canvas = tk.Canvas(stats_frame, bg='white')
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=stats_canvas.yview)
        stats_scrollable_frame = ttk.Frame(stats_canvas)
        
        stats_scrollable_frame.bind(
            "<Configure>",
            lambda e: stats_canvas.configure(scrollregion=stats_canvas.bbox("all"))
        )
        
        stats_canvas.create_window((0, 0), window=stats_scrollable_frame, anchor="nw")
        stats_canvas.configure(yscrollcommand=stats_scrollbar.set)
        
        stats_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statistics grid
        stats_grid = ttk.Frame(stats_scrollable_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.stats_display = {}
        stat_items = [
            ("Total Lines", "total_lines", "#3498db"),
            ("Unique IPs", "unique_ips", "#2ecc71"),
            ("Suspicious Activities", "suspicious", "#e74c3c"),
            ("Threat Level", "threat_level", "#f39c12"),
            ("Time Range", "time_range", "#9b59b6"),
            ("Attack Types", "attack_types", "#1abc9c")
        ]
        
        for i, (title, key, color) in enumerate(stat_items):
            frame = tk.Frame(stats_grid, bg='white', relief=tk.RAISED, bd=1)
            frame.grid(row=i//3, column=i%3, padx=10, pady=10, sticky="nsew")
            stats_grid.grid_rowconfigure(i//3, weight=1)
            stats_grid.grid_columnconfigure(i%3, weight=1)
            
            # Color bar
            color_bar = tk.Frame(frame, bg=color, height=5)
            color_bar.pack(fill=tk.X)
            
            # Content
            content = tk.Frame(frame, bg='white')
            content.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)
            
            # Title
            title_label = tk.Label(content, text=title, 
                                 font=('Arial', 11, 'bold'),
                                 bg='white',
                                 fg=self.colors['dark'])
            title_label.pack(pady=(0, 10))
            
            # Value
            value_label = tk.Label(content, text="N/A",
                                 font=('Arial', 14),
                                 bg='white',
                                 fg=color)
            value_label.pack()
            
            self.stats_display[key] = value_label
        
        # Threats tab
        threats_frame = ttk.Frame(notebook)
        notebook.add(threats_frame, text="⚠️ Threats")
        
        # Create scrollable threats frame
        threats_canvas = tk.Canvas(threats_frame, bg='white')
        threats_scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=threats_canvas.yview)
        threats_scrollable_frame = ttk.Frame(threats_canvas)
        
        threats_scrollable_frame.bind(
            "<Configure>",
            lambda e: threats_canvas.configure(scrollregion=threats_canvas.bbox("all"))
        )
        
        threats_canvas.create_window((0, 0), window=threats_scrollable_frame, anchor="nw")
        threats_canvas.configure(yscrollcommand=threats_scrollbar.set)
        
        threats_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        threats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threats treeview
        columns = ('Type', 'Count', 'Severity', 'Description')
        self.threats_tree = ttk.Treeview(threats_scrollable_frame, columns=columns, show='headings', height=15)
        
        col_widths = {'Type': 120, 'Count': 80, 'Severity': 100, 'Description': 250}
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars to treeview
        tree_scrollbar = ttk.Scrollbar(threats_scrollable_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Timeline tab
        timeline_frame = ttk.Frame(notebook)
        notebook.add(timeline_frame, text="📅 Timeline")
        
        # Create scrollable timeline frame
        timeline_canvas = tk.Canvas(timeline_frame, bg='white')
        timeline_scrollbar = ttk.Scrollbar(timeline_frame, orient=tk.VERTICAL, command=timeline_canvas.yview)
        timeline_scrollable_frame = ttk.Frame(timeline_canvas)
        
        timeline_scrollable_frame.bind(
            "<Configure>",
            lambda e: timeline_canvas.configure(scrollregion=timeline_canvas.bbox("all"))
        )
        
        timeline_canvas.create_window((0, 0), window=timeline_scrollable_frame, anchor="nw")
        timeline_canvas.configure(yscrollcommand=timeline_scrollbar.set)
        
        timeline_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        timeline_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Timeline text widget
        self.timeline_text = tk.Text(timeline_scrollable_frame, wrap=tk.WORD, height=15, width=80)
        text_scrollbar = ttk.Scrollbar(timeline_scrollable_frame, orient=tk.VERTICAL, command=self.timeline_text.yview)
        self.timeline_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.timeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        ttk.Button(button_frame, text="🔍 Analyze Log", 
                  command=self.analyze_log,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear", 
                  command=self.clear_log_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💾 Export Report", 
                  command=self.export_log_report).pack(side=tk.LEFT, padx=5)
    
    def show_packet_sniffer(self):
        """Show professional packet sniffer interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="📡 Packet Sniffer")
        
        if not SCAPY_AVAILABLE:
            self.show_dependency_warning("scapy", "Packet Sniffer")
            return
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Main container with tabs
        notebook = ttk.Notebook(main_scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Capture tab
        capture_frame = ttk.Frame(notebook)
        notebook.add(capture_frame, text="🎯 Capture")
        
        # Create scrollable capture frame
        capture_canvas = tk.Canvas(capture_frame, bg='white')
        capture_scrollbar = ttk.Scrollbar(capture_frame, orient=tk.VERTICAL, command=capture_canvas.yview)
        capture_scrollable_frame = ttk.Frame(capture_canvas)
        
        capture_scrollable_frame.bind(
            "<Configure>",
            lambda e: capture_canvas.configure(scrollregion=capture_canvas.bbox("all"))
        )
        
        capture_canvas.create_window((0, 0), window=capture_scrollable_frame, anchor="nw")
        capture_canvas.configure(yscrollcommand=capture_scrollbar.set)
        
        capture_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        capture_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configuration
        config_frame = ttk.LabelFrame(capture_scrollable_frame, text="Capture Settings", padding=20)
        config_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Packet count
        ttk.Label(config_frame, text="Packet Count:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.packet_count_var = tk.StringVar(value="50")
        count_spin = ttk.Spinbox(config_frame, from_=1, to=10000, 
                                textvariable=self.packet_count_var, width=10)
        count_spin.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Timeout
        ttk.Label(config_frame, text="Timeout (seconds):").grid(row=0, column=2, sticky=tk.W, pady=5, padx=(20,0))
        self.timeout_var = tk.StringVar(value="30")
        timeout_spin = ttk.Spinbox(config_frame, from_=1, to=300, 
                                  textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=0, column=3, padx=10, pady=5, sticky=tk.W)
        
        # BPF Filter
        ttk.Label(config_frame, text="BPF Filter:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.filter_entry = ttk.Entry(config_frame, width=50)
        self.filter_entry.grid(row=1, column=1, columnspan=3, padx=10, pady=5, sticky=tk.W+tk.E)
        
        # Quick filters
        filter_frame = ttk.Frame(config_frame)
        filter_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W, pady=5)
        
        quick_filters = {
            "TCP Only": "tcp",
            "HTTP": "tcp port 80",
            "DNS": "udp port 53",
            "ARP": "arp",
            "ICMP": "icmp"
        }
        
        for text, filter_exp in quick_filters.items():
            btn = ttk.Button(filter_frame, text=text,
                           command=lambda f=filter_exp: self.filter_entry.delete(0, tk.END) or self.filter_entry.insert(0, f))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Live capture display
        capture_display_frame = ttk.LabelFrame(capture_scrollable_frame, text="Live Capture", padding=10)
        capture_display_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Text widget for capture output with scrollbars
        text_frame = tk.Frame(capture_display_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.capture_text = tk.Text(text_frame, 
                                   wrap=tk.WORD,
                                   font=('Consolas', 9),
                                   bg='#1e1e1e',
                                   fg='#d4d4d4',
                                   height=20)
        
        v_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.capture_text.yview)
        h_scrollbar = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self.capture_text.xview)
        self.capture_text.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.capture_text.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        # Control buttons
        button_frame = ttk.Frame(capture_scrollable_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="🎯 Start Capture", 
                  command=self.start_packet_capture,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🛑 Stop Capture", 
                  command=self.stop_packet_capture,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear", 
                  command=lambda: self.capture_text.delete(1.0, tk.END) or self.stats_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💾 Save Capture", 
                  command=self.save_packet_capture).pack(side=tk.LEFT, padx=5)
        
        # Statistics tab
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Statistics")
        
        # Create scrollable stats frame
        stats_canvas = tk.Canvas(stats_frame, bg='white')
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=stats_canvas.yview)
        stats_scrollable_frame = ttk.Frame(stats_canvas)
        
        stats_scrollable_frame.bind(
            "<Configure>",
            lambda e: stats_canvas.configure(scrollregion=stats_canvas.bbox("all"))
        )
        
        stats_canvas.create_window((0, 0), window=stats_scrollable_frame, anchor="nw")
        stats_canvas.configure(yscrollcommand=stats_scrollbar.set)
        
        stats_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Stats text widget
        self.stats_text = tk.Text(stats_scrollable_frame, wrap=tk.WORD, height=20, width=80)
        text_scrollbar = ttk.Scrollbar(stats_scrollable_frame, orient=tk.VERTICAL, command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.stats_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def show_http_auditor(self):
        """Show enhanced HTTP auditor interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🛡️ HTTP Security Auditor")
        
        if not REQUESTS_AVAILABLE:
            self.show_dependency_warning("requests", "HTTP Auditor")
            return
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # URL input
        url_frame = ttk.LabelFrame(main_scrollable_frame, text="Target URL", padding=20)
        url_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        ttk.Label(url_frame, text="Enter URL to audit:").pack(anchor=tk.W, pady=5)
        
        self.audit_url_entry = ttk.Entry(url_frame, width=60)
        self.audit_url_entry.pack(fill=tk.X, pady=5)
        self.audit_url_entry.insert(0, "https://example.com")
        
        # Quick URLs
        quick_frame = ttk.Frame(url_frame)
        quick_frame.pack(fill=tk.X, pady=5)
        
        quick_urls = [
            "https://google.com",
            "https://github.com",
            "https://httpbin.org",
            "http://neverssl.com"
        ]
        
        for url in quick_urls:
            btn = ttk.Button(quick_frame, text=url, width=15,
                           command=lambda u=url: self.audit_url_entry.delete(0, tk.END) or self.audit_url_entry.insert(0, u))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Results display
        results_frame = ttk.LabelFrame(main_scrollable_frame, text="Security Assessment", padding=20)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Create scrollable results frame
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Grade display
        grade_frame = tk.Frame(results_scrollable_frame)
        grade_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.grade_label = tk.Label(grade_frame, text="GRADE: N/A", 
                                   font=('Arial', 36, 'bold'),
                                   fg=self.colors['dark'])
        self.grade_label.pack()
        
        self.score_label = tk.Label(grade_frame, text="Score: 0/100",
                                  font=('Arial', 14),
                                  fg='#666')
        self.score_label.pack()
        
        # Headers display
        headers_frame = ttk.LabelFrame(results_scrollable_frame, text="Security Headers", padding=10)
        headers_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas for scrollable headers
        headers_canvas = tk.Canvas(headers_frame)
        headers_scrollbar = ttk.Scrollbar(headers_frame, orient=tk.VERTICAL, command=headers_canvas.yview)
        headers_scrollable_frame = ttk.Frame(headers_canvas)
        
        headers_scrollable_frame.bind(
            "<Configure>",
            lambda e: headers_canvas.configure(scrollregion=headers_canvas.bbox("all"))
        )
        
        headers_canvas.create_window((0, 0), window=headers_scrollable_frame, anchor="nw")
        headers_canvas.configure(yscrollcommand=headers_scrollbar.set)
        
        headers_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        headers_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Header check widgets (will be populated after audit)
        self.header_widgets = {}
        
        # Button
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        ttk.Button(button_frame, text="🔍 Run Security Audit", 
                  command=self.run_http_audit,
                  style='Success.TButton').pack(pady=10)
    
    def show_vuln_scanner(self):
        """Show vulnerability scanner interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="⚠️ Vulnerability Scanner")
        
        if not REQUESTS_AVAILABLE:
            self.show_dependency_warning("requests", "Vulnerability Scanner")
            return
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # URL input
        url_frame = ttk.LabelFrame(main_scrollable_frame, text="Target URL", padding=20)
        url_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        ttk.Label(url_frame, text="Enter URL to scan:").pack(anchor=tk.W, pady=5)
        
        self.vuln_url_entry = ttk.Entry(url_frame, width=60)
        self.vuln_url_entry.pack(fill=tk.X, pady=5)
        self.vuln_url_entry.insert(0, "http://testphp.vulnweb.com")
        
        # Scan types
        scan_frame = ttk.LabelFrame(main_scrollable_frame, text="Scan Types", padding=15)
        scan_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        self.scan_vars = {
            'sql_injection': tk.BooleanVar(value=True),
            'xss': tk.BooleanVar(value=True),
            'path_traversal': tk.BooleanVar(value=True),
            'command_injection': tk.BooleanVar(value=False)
        }
        
        for i, (scan_type, var) in enumerate(self.scan_vars.items()):
            cb = ttk.Checkbutton(scan_frame, text=scan_type.replace('_', ' ').title(), variable=var)
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=10, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_scrollable_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Create scrollable results frame
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Results text widget
        self.vuln_results_text = tk.Text(results_scrollable_frame, wrap=tk.WORD, height=15, width=80)
        text_scrollbar = ttk.Scrollbar(results_scrollable_frame, orient=tk.VERTICAL, command=self.vuln_results_text.yview)
        self.vuln_results_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.vuln_results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        ttk.Button(button_frame, text="🔍 Start Scan", 
                  command=self.start_vuln_scan,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear", 
                  command=lambda: self.vuln_results_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
    
    def show_ssl_checker(self):
        """Show SSL/TLS checker interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🔐 SSL/TLS Checker")
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Hostname input
        host_frame = ttk.LabelFrame(main_scrollable_frame, text="SSL/TLS Check", padding=20)
        host_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        ttk.Label(host_frame, text="Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ssl_host_entry = ttk.Entry(host_frame, width=40)
        self.ssl_host_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.ssl_host_entry.insert(0, "google.com")
        
        ttk.Label(host_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, pady=5, padx=(20,0))
        self.ssl_port_entry = ttk.Entry(host_frame, width=10)
        self.ssl_port_entry.grid(row=0, column=3, padx=10, pady=5, sticky=tk.W)
        self.ssl_port_entry.insert(0, "443")
        
        # Quick hosts
        quick_frame = ttk.Frame(host_frame)
        quick_frame.grid(row=1, column=1, columnspan=3, sticky=tk.W, pady=5)
        
        quick_hosts = ["google.com", "github.com", "microsoft.com", "apple.com"]
        for host in quick_hosts:
            btn = ttk.Button(quick_frame, text=host, width=12,
                           command=lambda h=host: self.ssl_host_entry.delete(0, tk.END) or self.ssl_host_entry.insert(0, h))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Results area
        results_frame = ttk.LabelFrame(main_scrollable_frame, text="SSL/TLS Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Create scrollable results frame
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Results text widget
        self.ssl_results_text = tk.Text(results_scrollable_frame, wrap=tk.WORD, height=15, width=80)
        text_scrollbar = ttk.Scrollbar(results_scrollable_frame, orient=tk.VERTICAL, command=self.ssl_results_text.yview)
        self.ssl_results_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.ssl_results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        ttk.Button(button_frame, text="🔍 Check SSL", 
                  command=self.check_ssl,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear", 
                  command=lambda: self.ssl_results_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
    
    def show_password_checker(self):
        """Show password strength checker interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="🔑 Password Strength Checker")
        
        # Create scrollable main frame
        main_canvas = tk.Canvas(self.content_frame, bg='white')
        main_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=main_canvas.yview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Password input
        pass_frame = ttk.LabelFrame(main_scrollable_frame, text="Password Check", padding=20)
        pass_frame.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        ttk.Label(pass_frame, text="Enter Password:").pack(anchor=tk.W, pady=5)
        
        self.password_entry = ttk.Entry(pass_frame, width=60, show="•")
        self.password_entry.pack(fill=tk.X, pady=5)
        
        # Show/hide checkbox
        self.show_password_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(pass_frame, text="Show password", variable=self.show_password_var,
                                 command=lambda: self.password_entry.config(show="" if self.show_password_var.get() else "•"))
        show_cb.pack(anchor=tk.W, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_scrollable_frame, text="Password Analysis", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=20)
        
        # Create scrollable results frame
        results_canvas = tk.Canvas(results_frame, bg='white')
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_scrollable_frame = ttk.Frame(results_canvas)
        
        results_scrollable_frame.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_scrollable_frame, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Password results text widget
        self.password_results_text = tk.Text(results_scrollable_frame, wrap=tk.WORD, height=15, width=80)
        text_scrollbar = ttk.Scrollbar(results_scrollable_frame, orient=tk.VERTICAL, command=self.password_results_text.yview)
        self.password_results_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.password_results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_scrollable_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0), padx=20)
        
        ttk.Button(button_frame, text="🔍 Analyze Password", 
                  command=self.check_password_strength,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Clear", 
                  command=lambda: self.password_results_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🎲 Generate Strong", 
                  command=self.generate_password).pack(side=tk.LEFT, padx=5)
    
    def show_reports(self):
        """Show reports interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="📈 Reports & Analytics")
        
        # Create scrollable reports frame
        reports_canvas = tk.Canvas(self.content_frame, bg='white')
        reports_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=reports_canvas.yview)
        reports_scrollable_frame = ttk.Frame(reports_canvas)
        
        reports_scrollable_frame.bind(
            "<Configure>",
            lambda e: reports_canvas.configure(scrollregion=reports_canvas.bbox("all"))
        )
        
        reports_canvas.create_window((0, 0), window=reports_scrollable_frame, anchor="nw")
        reports_canvas.configure(yscrollcommand=reports_scrollbar.set)
        
        reports_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        reports_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        placeholder = tk.Label(reports_scrollable_frame, 
                              text="📊 Advanced Reporting Module\n\n" +
                                   "This feature is under development.\n" +
                                   "Coming in version 3.0:\n" +
                                   "• Historical scan data\n" +
                                   "• Trend analysis\n" +
                                   "• PDF/Excel export\n" +
                                   "• Compliance reporting\n" +
                                   "• Dashboard visualization\n\n" +
                                   "Available Statistics:\n" +
                                   f"• Ports Scanned: {self.scan_stats['ports_scanned']}\n" +
                                   f"• Files Hashed: {self.scan_stats['files_hashed']}\n" +
                                   f"• Packets Captured: {self.scan_stats['packets_captured']}\n" +
                                   f"• Threats Detected: {self.scan_stats['threats_detected']}",
                              font=('Arial', 12),
                              foreground=self.colors['info'],
                              justify=tk.LEFT,
                              padx=50,
                              pady=50)
        placeholder.pack(expand=True)
    
    def show_settings(self):
        """Show settings interface with scrollbars"""
        self.clear_content()
        self.title_label.config(text="⚙️ Settings & Configuration")
        
        # Create scrollable settings frame
        settings_canvas = tk.Canvas(self.content_frame, bg='white')
        settings_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=settings_canvas.yview)
        settings_scrollable_frame = ttk.Frame(settings_canvas)
        
        settings_scrollable_frame.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        )
        
        settings_canvas.create_window((0, 0), window=settings_scrollable_frame, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        
        settings_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        settings_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Settings notebook
        notebook = ttk.Notebook(settings_scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # General settings
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        general_label = tk.Label(general_frame, 
                                text="General Settings\n\n" +
                                     "• Theme Selection\n" +
                                     "• Default Port Ranges\n" +
                                     "• Thread Pool Size\n" +
                                     "• Log Retention\n" +
                                     "• Auto-save Interval\n\n" +
                                     "Available in version 3.0",
                                font=('Arial', 12),
                                justify=tk.LEFT,
                                padx=50,
                                pady=50)
        general_label.pack(expand=True)
        
        # Network settings
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Network")
        
        network_label = tk.Label(network_frame, 
                                text="Network Settings\n\n" +
                                     "• Default Timeout\n" +
                                     "• Proxy Configuration\n" +
                                     "• DNS Servers\n" +
                                     "• Network Interface\n" +
                                     "• Packet Capture Options\n\n" +
                                     "Available in version 3.0",
                                font=('Arial', 12),
                                justify=tk.LEFT,
                                padx=50,
                                pady=50)
        network_label.pack(expand=True)
        
        # Security settings
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security")
        
        security_label = tk.Label(security_frame, 
                                 text="Security Settings\n\n" +
                                      "• API Keys\n" +
                                      "• Encryption Options\n" +
                                      "• Certificate Validation\n" +
                                      "• Security Headers\n" +
                                      "• Password Policies\n\n" +
                                      "Available in version 3.0",
                                 font=('Arial', 12),
                                 justify=tk.LEFT,
                                 padx=50,
                                 pady=50)
        security_label.pack(expand=True)
    
    def show_dependency_warning(self, library, feature):
        """Show dependency warning with scrollbars"""
        self.clear_content()
        
        # Create scrollable warning frame
        warning_canvas = tk.Canvas(self.content_frame, bg='white')
        warning_scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=warning_canvas.yview)
        warning_scrollable_frame = ttk.Frame(warning_canvas)
        
        warning_scrollable_frame.bind(
            "<Configure>",
            lambda e: warning_canvas.configure(scrollregion=warning_canvas.bbox("all"))
        )
        
        warning_canvas.create_window((0, 0), window=warning_scrollable_frame, anchor="nw")
        warning_canvas.configure(yscrollcommand=warning_scrollbar.set)
        
        warning_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        warning_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        warning_label = tk.Label(warning_scrollable_frame, 
                                text=f"⚠️ {library.upper()} library not installed!\n\n" +
                                     f"{feature} requires the '{library}' library.\n\n" +
                                     f"Install it with:\n" +
                                     f"pip install {library}\n\n" +
                                     f"Or install all dependencies:\n" +
                                     f"pip install requests scapy\n\n" +
                                     f"Note: You may need to restart the application\n" +
                                     f"after installing the missing library.",
                                font=('Arial', 12),
                                foreground=self.colors['danger'],
                                justify=tk.CENTER,
                                padx=50,
                                pady=50)
        warning_label.pack(expand=True)
        
        # Install button
        install_btn = ttk.Button(warning_scrollable_frame, text=f"📦 Install {library}",
                                command=lambda: self.install_dependency(library),
                                style='Info.TButton')
        install_btn.pack(pady=20)
    
    # ============================================================================
    # TOOL ACTIONS
    # ============================================================================
    
    def quick_scan_localhost(self):
        """Quick scan localhost"""
        self.log_output("🚀 Starting quick port scan on localhost...", "info")
        open_ports = self.tools['port_scanner'].threaded_scan("localhost", "1-1000", 50)
        self.log_output(f"✅ Quick scan complete. Found {len(open_ports)} open ports.", "success")
        self.update_statistics('ports_scanned', 1000)
    
    def quick_network_capture(self):
        """Quick network capture"""
        if not SCAPY_AVAILABLE:
            self.log_output("❌ Scapy not available for packet capture", "error")
            return
        
        self.log_output("🎯 Starting quick network capture (10 packets)...", "info")
        
        def quick_capture():
            packets = self.tools['packet_sniffer'].start_sniffing(count=10, timeout=10)
            self.update_statistics('packets_captured', len(packets))
        
        threading.Thread(target=quick_capture, daemon=True).start()
    
    def check_system_files(self):
        """Check system files integrity"""
        self.log_output("🔍 Checking system files integrity...", "info")
        
        # Platform-specific important files
        if sys.platform == "win32":
            important_files = [
                r"C:\Windows\System32\drivers\etc\hosts",
                r"C:\Windows\System32\kernel32.dll",
                r"C:\Windows\win.ini",
                r"C:\Windows\System32\cmd.exe"
            ]
        elif sys.platform == "linux":
            important_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/bin/bash"
            ]
        else:
            important_files = []
        
        for file in important_files:
            if os.path.exists(file):
                try:
                    file_size = os.path.getsize(file)
                    self.log_output(f"✅ {file} - {self._format_file_size(file_size)}", "success")
                except:
                    self.log_output(f"✅ {file} - Exists", "info")
            else:
                self.log_output(f"❌ {file} - Missing", "warning")
    
    def _format_file_size(self, size_bytes):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def generate_report(self):
        """Generate comprehensive security report"""
        self.log_output("📊 Generating security report...", "info")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'python_version': sys.version,
                'platform': sys.platform,
                'requests_available': REQUESTS_AVAILABLE,
                'scapy_available': SCAPY_AVAILABLE
            },
            'statistics': self.scan_stats,
            'tools': {
                'port_scanner': 'Enhanced',
                'file_checker': 'Enhanced',
                'log_parser': 'Advanced',
                'packet_sniffer': 'Professional',
                'http_auditor': 'Enhanced'
            }
        }
        
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            self.log_output(f"✅ Report saved to: {filename}", "success")
        except Exception as e:
            self.log_output(f"❌ Error saving report: {str(e)}", "error")
    
    def start_port_scan(self):
        """Start enhanced port scan"""
        target = self.target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target hostname or IP address")
            return
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Show progress
        self.status_label.config(text="🔄 Scanning ports...")
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        self.progress_bar.start()
        
        def scan_thread():
            start_time = time.time()
            
            try:
                open_ports = self.tools['port_scanner'].threaded_scan(
                    target, 
                    port_range, 
                    int(self.threads_var.get())
                )
                
                # Update results tree
                for port, service, banner in sorted(open_ports, key=lambda x: x[0]):
                    banner_preview = banner[:50] + "..." if banner and len(banner) > 50 else banner or ""
                    self.results_tree.insert('', tk.END, values=(port, service, "Open", banner_preview))
                
                # Update statistics
                self.update_statistics('ports_scanned', len(open_ports))
                
                # Update summary
                elapsed = time.time() - start_time
                if hasattr(self, 'summary_labels'):
                    self.summary_labels['total'].config(text=f"Total: {self._count_ports(port_range)}")
                    self.summary_labels['open'].config(text=f"Open: {len(open_ports)}")
                    self.summary_labels['closed'].config(text=f"Closed: {self._count_ports(port_range) - len(open_ports)}")
                    self.summary_labels['duration'].config(text=f"Duration: {elapsed:.1f}s")
                
                self.log_output(f"✅ Port scan completed in {elapsed:.1f} seconds", "success")
                
            except Exception as e:
                self.log_output(f"❌ Scan error: {str(e)}", "error")
            finally:
                # Hide progress bar
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def _count_ports(self, port_range):
        """Count number of ports in a range"""
        try:
            if "-" in port_range:
                start, end = map(int, port_range.split("-"))
                return end - start + 1
            elif "," in port_range:
                return len(port_range.split(","))
            else:
                return 1
        except:
            return 0
    
    def clear_results(self):
        """Clear scan results"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        if hasattr(self, 'summary_labels'):
            for label in self.summary_labels.values():
                label.config(text="0")
        
        self.log_output("🧹 Scan results cleared", "info")
    
    def copy_scan_results(self):
        """Copy scan results to clipboard"""
        if not self.results_tree.get_children():
            messagebox.showinfo("Info", "No results to copy")
            return
        
        results_text = "Port,Service,Status,Banner\n"
        for item in self.results_tree.get_children():
            values = self.results_tree.item(item)['values']
            results_text += f"{values[0]},{values[1]},{values[2]},{values[3]}\n"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(results_text)
        self.log_output("📋 Scan results copied to clipboard", "success")
    
    def export_results(self):
        """Export scan results"""
        if not self.results_tree.get_children():
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            initialfile=f"port_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Export as JSON
                    results = []
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        results.append({
                            'port': values[0],
                            'service': values[1],
                            'status': values[2],
                            'banner': values[3]
                        })
                    
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2)
                else:
                    # Export as CSV/Text
                    with open(filename, 'w') as f:
                        f.write("Port,Service,Status,Banner\n")
                        for item in self.results_tree.get_children():
                            values = self.results_tree.item(item)['values']
                            f.write(f"{values[0]},{values[1]},{values[2]},{values[3]}\n")
                self.log_output(f"✅ Results exported to: {filename}", "success")
            except Exception as e:
                self.log_output(f"❌ Export error: {str(e)}", "error")
    
    def browse_file(self, entry_widget=None):
        """Browse for a file"""
        filename = filedialog.askopenfilename(
            title="Select File",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("Executables", "*.exe"),
                ("Python files", "*.py")
            ]
        )
        if filename:
            if entry_widget:
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, filename)
            elif hasattr(self, 'file_path_entry'):
                self.file_path_entry.delete(0, tk.END)
                self.file_path_entry.insert(0, filename)
            else:
                # Create a new entry if none exists
                self.log_output(f"📁 Selected file: {filename}", "info")
                return filename
            self.log_output(f"📁 Selected file: {filename}", "info")
        return None
    
    def browse_directory(self):
        """Browse for a directory"""
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            self.dir_path_entry.delete(0, tk.END)
            self.dir_path_entry.insert(0, directory)
            self.log_output(f"📁 Selected directory: {directory}", "info")
    
    def paste_from_clipboard(self):
        """Paste from clipboard to file path entry"""
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                self.file_path_entry.delete(0, tk.END)
                self.file_path_entry.insert(0, clipboard_text)
                self.log_output("📋 Pasted from clipboard", "info")
        except:
            self.log_output("❌ Clipboard is empty or contains invalid data", "warning")
    
    def calculate_single_hash(self):
        """Calculate hash for single file"""
        file_path = self.file_path_entry.get().strip()
        algorithm = self.algorithm_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        def calculate_thread():
            self.status_label.config(text="🔄 Calculating hash...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                hash_value = self.tools['file_checker'].calculate_hash(file_path, algorithm)
                if hash_value:
                    # Update expected hash field
                    self.expected_hash_entry.delete(1.0, tk.END)
                    self.expected_hash_entry.insert(1.0, hash_value)
                    self.update_statistics('files_hashed', 1)
                    self.log_output(f"✅ Hash calculation complete", "success")
                    self.log_output(f"🔑 {algorithm.upper()}: {hash_value}", "info")
            except Exception as e:
                self.log_output(f"❌ Error calculating hash: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=calculate_thread, daemon=True).start()
    
    def verify_single_file(self):
        """Verify single file integrity"""
        file_path = self.file_path_entry.get().strip()
        algorithm = self.algorithm_var.get()
        expected_hash = self.expected_hash_entry.get(1.0, tk.END).strip()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        if not expected_hash:
            self.log_output("⚠️ No expected hash provided - will only calculate hash", "warning")
        
        def verify_thread():
            self.status_label.config(text="🔄 Verifying file...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                result = self.tools['file_checker'].verify_file(file_path, expected_hash or None, algorithm)
                if result is not None:
                    self.update_statistics('files_hashed', 1)
            except Exception as e:
                self.log_output(f"❌ Verification error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=verify_thread, daemon=True).start()
    
    def create_baseline(self):
        """Create directory baseline"""
        directory = self.dir_path_entry.get().strip()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory")
            return
        algorithm = self.baseline_algo.get()
        
        def baseline_thread():
            self.status_label.config(text="🔄 Creating baseline...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                baseline_file = self.tools['file_checker'].create_directory_baseline(directory, algorithm)
                if baseline_file:
                    self.log_output(f"✅ Baseline saved to: {baseline_file}", "success")
                    # Count files in baseline
                    try:
                        with open(baseline_file, 'r') as f:
                            baseline_data = json.load(f)
                            file_count = baseline_data.get('file_count', 0)
                            self.update_statistics('files_hashed', file_count)
                    except:
                        pass
            except Exception as e:
                self.log_output(f"❌ Baseline creation error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=baseline_thread, daemon=True).start()
    
    def load_custom_wordlist(self):
        """Load custom wordlist file"""
        filename = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[
                ("Text files", "*.txt"),
                ("Wordlists", "*.lst"),
                ("All files", "*.*")
            ]
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip()]
                self.log_output(f"📁 Loaded wordlist: {filename} ({len(words)} words)", "success")
                self.wordlist_var.set("Custom")
                # Store words for later use
                self.custom_wordlist = words
            except Exception as e:
                self.log_output(f"❌ Error loading wordlist: {str(e)}", "error")
    
    def start_directory_scan(self):
        """Start directory scan"""
        url = self.url_entry.get().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Clear previous results
        for item in self.dir_results_tree.get_children():
            self.dir_results_tree.delete(item)
        
        def scan_thread():
            self.status_label.config(text="🌐 Scanning directories...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                found_items = self.tools['directory_scanner'].brute_force(url)
                # Update results tree
                for item_url, status, size in found_items:
                    size_str = f"{size} bytes" if size > 0 else ""
                    self.dir_results_tree.insert('', tk.END, values=(item_url, status, size_str, ""))
                self.log_output(f"✅ Directory scan complete. Found {len(found_items)} items.", "success")
            except Exception as e:
                self.log_output(f"❌ Directory scan error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def export_dir_results(self):
        """Export directory scan results"""
        if not self.dir_results_tree.get_children():
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
            initialfile=f"directory_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("URL,Status,Size\n")
                    for item in self.dir_results_tree.get_children():
                        values = self.dir_results_tree.item(item)['values']
                        f.write(f"{values[0]},{values[1]},{values[2]}\n")
                self.log_output(f"✅ Results exported to: {filename}", "success")
            except Exception as e:
                self.log_output(f"❌ Export error: {str(e)}", "error")
    
    def analyze_log(self):
        """Analyze log file"""
        log_file = self.log_file_entry.get().strip()
        
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("Error", "Please select a valid log file")
            return
        
        # Clear previous analysis
        self.clear_log_analysis()
        
        def analysis_thread():
            self.status_label.config(text="📝 Analyzing log file...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                findings = self.tools['log_parser'].parse_log_file(log_file)
                if findings:
                    # Update statistics display
                    summary = findings['summary']
                    if 'total_lines' in self.stats_display:
                        self.stats_display['total_lines'].config(text=f"{summary['total_lines']:,}")
                    if 'unique_ips' in self.stats_display:
                        self.stats_display['unique_ips'].config(text=f"{len(summary['unique_ips']):,}")
                    if 'suspicious' in self.stats_display:
                        self.stats_display['suspicious'].config(text=f"{summary['suspicious_activity']:,}")
                    # Update threat level
                    threat_level = self.tools['log_parser']._calculate_threat_level(
                        summary['suspicious_activity'], 
                        len(summary['unique_ips'])
                    )
                    if 'threat_level' in self.stats_display:
                        self.stats_display['threat_level'].config(text=threat_level)
                    # Update threats tree
                    for attack_type, count in summary['attacks_by_type'].items():
                        severity = self.tools['log_parser'].suspicious_patterns.get(attack_type, {}).get('severity', 'medium')
                        description = self.tools['log_parser'].suspicious_patterns.get(attack_type, {}).get('description', '')
                        self.threats_tree.insert('', tk.END, 
                                               values=(attack_type, count, severity.upper(), description))
                    # Generate timeline
                    timeline_text = "📅 ATTACK TIMELINE\n"
                    timeline_text += "=" * 50 + "\n\n"
                    for event in summary.get('timeline', [])[:20]:
                        timestamp = event.get('timestamp', 'N/A')
                        attack_type = event.get('attack_type', 'Unknown')
                        severity = event.get('severity', 'medium')
                        source_ip = event.get('source_ip', 'Unknown')
                        severity_icon = "🔴" if severity == 'critical' else "🟠" if severity == 'high' else "🟡"
                        timeline_text += f"{severity_icon} [{timestamp}] {source_ip} → {attack_type}\n"
                    self.timeline_text.delete(1.0, tk.END)
                    self.timeline_text.insert(1.0, timeline_text)
                    # Update statistics
                    self.update_statistics('threats_detected', summary['suspicious_activity'])
                else:
                    self.log_output("ℹ️ No suspicious activities found in the log file", "info")
            except Exception as e:
                self.log_output(f"❌ Log analysis error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=analysis_thread, daemon=True).start()
    
    def clear_log_analysis(self):
        """Clear log analysis results"""
        # Clear statistics display
        for label in self.stats_display.values():
            label.config(text="N/A")
        # Clear threats tree
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        # Clear timeline
        if hasattr(self, 'timeline_text'):
            self.timeline_text.delete(1.0, tk.END)
        self.log_output("🧹 Log analysis cleared", "info")
    
    def export_log_report(self):
        """Export log analysis report"""
        if not self.threats_tree.get_children():
            messagebox.showinfo("Info", "No analysis results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            initialfile=f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("LOG ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    # Write statistics
                    f.write("STATISTICS:\n")
                    for key, label in self.stats_display.items():
                        value = label.cget("text")
                        f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
                    f.write("\nTHREATS DETECTED:\n")
                    for item in self.threats_tree.get_children():
                        values = self.threats_tree.item(item)['values']
                        f.write(f"  {values[0]}: {values[1]} incidents ({values[2]})\n")
                    # Write timeline
                    if hasattr(self, 'timeline_text'):
                        timeline = self.timeline_text.get(1.0, tk.END)
                        if timeline.strip():
                            f.write("\nTIMELINE:\n")
                            f.write(timeline)
                self.log_output(f"✅ Log report exported to: {filename}", "success")
            except Exception as e:
                self.log_output(f"❌ Export error: {str(e)}", "error")
    
    def start_packet_capture(self):
        """Start professional packet capture"""
        try:
            # Capture values BEFORE starting thread
            count = int(self.packet_count_var.get())
            timeout = int(self.timeout_var.get())
            filter_exp = self.filter_entry.get().strip() or None
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers")
            return
        
        # Clear previous capture
        self.capture_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        def capture_thread(count, timeout, filter_exp):
            """Thread function with captured parameters"""
            self.status_label.config(text="📡 Capturing packets...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                # Pass captured parameters to the sniffer
                packets = self.tools['packet_sniffer'].start_sniffing(
                    count=count, 
                    timeout=timeout, 
                    filter_exp=filter_exp
                )
                if packets:
                    self.update_statistics('packets_captured', len(packets))
                    # Update statistics display
                    stats_text = "📊 PACKET CAPTURE STATISTICS\n"
                    stats_text += "=" * 50 + "\n\n"
                    # Check if protocol_stats exists
                    if hasattr(self.tools['packet_sniffer'], 'protocol_stats'):
                        for protocol, packet_count in self.tools['packet_sniffer'].protocol_stats.items():
                            if packet_count > 0:
                                stats_text += f"{protocol}: {packet_count} packets\n"
                    self.stats_text.delete(1.0, tk.END)
                    self.stats_text.insert(1.0, stats_text)
                self.log_output(f"✅ Packet capture completed", "success")
            except Exception as e:
                self.log_output(f"❌ Capture error: {str(e)}", "error")
                import traceback
                self.log_output(f"🔍 Error details: {traceback.format_exc()}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        # Start thread with captured parameters
        threading.Thread(
            target=capture_thread, 
            args=(count, timeout, filter_exp), 
            daemon=True
        ).start()
    
    def stop_packet_capture(self):
        """Stop packet capture"""
        if hasattr(self.tools['packet_sniffer'], 'stop_sniffing'):
            self.tools['packet_sniffer'].stop_sniffing()
            self.log_output("🛑 Packet capture stopped", "warning")
        else:
            self.log_output("❌ Stop capture not implemented for this version", "error")
    
    def save_packet_capture(self):
        """Save packet capture to file"""
        if not self.tools['packet_sniffer'].captured_packets:
            messagebox.showinfo("Info", "No packets captured to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[
                ("PCAP files", "*.pcap"),
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            initialfile=f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Save as JSON
                    with open(filename, 'w') as f:
                        json.dump(self.tools['packet_sniffer'].captured_packets, f, indent=2, default=str)
                elif filename.endswith('.txt'):
                    # Save as text
                    with open(filename, 'w') as f:
                        for packet in self.tools['packet_sniffer'].captured_packets:
                            f.write(str(packet) + "\n" + "="*50 + "\n")
                else:
                    # Note: Would need to implement actual PCAP saving with scapy
                    self.log_output("⚠️ PCAP saving requires additional implementation", "warning")
                    return
                self.log_output(f"✅ Capture saved to: {filename}", "success")
            except Exception as e:
                self.log_output(f"❌ Save error: {str(e)}", "error")
    
    def run_http_audit(self):
        """Run enhanced HTTP security audit"""
        url = self.audit_url_entry.get().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        def audit_thread():
            self.status_label.config(text="🛡️ Auditing HTTP headers...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                results = self.tools['http_auditor'].audit_url(url)
                if results:
                    # Update grade display
                    grade = results.get('grade', 'N/A')
                    score = results.get('score', 0)
                    color = self._get_grade_color(grade)
                    self.grade_label.config(text=f"GRADE: {grade}", fg=color)
                    self.score_label.config(text=f"Score: {score}/100")
                    # Update header widgets
                    for widget in self.header_widgets.values():
                        widget.destroy()
                    self.header_widgets.clear()
                    # Display headers
                    # Find the scrollable frame
                    scrollable_frame = None
                    for widget in self.content_frame.winfo_children():
                        if isinstance(widget, tk.Canvas):
                            for child in widget.winfo_children():
                                if isinstance(child, tk.Frame):
                                    scrollable_frame = child
                                    break
                            if scrollable_frame:
                                break
                    
                    if scrollable_frame:
                        # Present headers
                        for header in results.get('present_headers', []):
                            frame = ttk.Frame(scrollable_frame)
                            frame.pack(fill=tk.X, pady=2)
                            # Status icon
                            icon = "✅" if header.get('value') else "⚠️"
                            icon_label = tk.Label(frame, text=icon, font=('Arial', 12))
                            icon_label.pack(side=tk.LEFT, padx=5)
                            # Header name
                            name_label = tk.Label(frame, text=header['name'], 
                                                 font=('Arial', 10, 'bold'),
                                                 width=30,
                                                 anchor=tk.W)
                            name_label.pack(side=tk.LEFT, padx=5)
                            # Header value (truncated)
                            value = header.get('value', '')
                            value_preview = value[:50] + "..." if len(value) > 50 else value
                            value_label = tk.Label(frame, text=value_preview,
                                                  font=('Arial', 9),
                                                  foreground='#666',
                                                  anchor=tk.W)
                            value_label.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
                            self.header_widgets[header['name']] = frame
                        # Missing headers
                        if results.get('missing_headers'):
                            sep = ttk.Separator(scrollable_frame, orient='horizontal')
                            sep.pack(fill=tk.X, pady=10)
                            self.header_widgets['separator'] = sep
                            missing_label = tk.Label(scrollable_frame, 
                                                    text="❌ MISSING HEADERS:",
                                                    font=('Arial', 10, 'bold'),
                                                    foreground=self.colors['danger'])
                            missing_label.pack(anchor=tk.W, pady=5)
                            self.header_widgets['missing_label'] = missing_label
                            for header in results['missing_headers']:
                                frame = ttk.Frame(scrollable_frame)
                                frame.pack(fill=tk.X, pady=2)
                                icon_label = tk.Label(frame, text="❌", font=('Arial', 12))
                                icon_label.pack(side=tk.LEFT, padx=5)
                                name_label = tk.Label(frame, text=header['name'], 
                                                     font=('Arial', 10),
                                                     foreground=self.colors['danger'],
                                                     width=30,
                                                     anchor=tk.W)
                                name_label.pack(side=tk.LEFT, padx=5)
                                desc = self.tools['http_auditor'].security_headers.get(header['name'], {}).get('description', '')
                                desc_label = tk.Label(frame, text=desc,
                                                     font=('Arial', 9),
                                                     foreground='#999',
                                                     anchor=tk.W)
                                desc_label.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
                                
                                self.header_widgets[f"missing_{header['name']}"] = frame
                else:
                    self.grade_label.config(text="GRADE: N/A", foreground=self.colors['dark'])
                    self.score_label.config(text="Score: N/A")
            except Exception as e:
                self.log_output(f"❌ HTTP audit error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=audit_thread, daemon=True).start()
    
    def _get_grade_color(self, grade):
        """Get color for grade"""
        colors = {
            'A': '#27ae60',
            'B': '#3498db',
            'C': '#f39c12',
            'D': '#e74c3c',
            'F': '#c0392b'
        }
        return colors.get(grade, self.colors['dark'])
    
    def start_vuln_scan(self):
        """Start vulnerability scan"""
        url = self.vuln_url_entry.get().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Get selected scan types
        scan_types = [scan_type for scan_type, var in self.scan_vars.items() if var.get()]
        
        if not scan_types:
            messagebox.showerror("Error", "Please select at least one scan type")
            return
        
        def scan_thread():
            self.status_label.config(text="⚠️ Scanning for vulnerabilities...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                results = self.tools['vuln_scanner'].scan_url(url, scan_types)
                # Display results
                self.vuln_results_text.delete(1.0, tk.END)
                self.vuln_results_text.insert(1.0, f"VULNERABILITY SCAN RESULTS\n")
                self.vuln_results_text.insert(tk.END, f"{'='*50}\n\n")
                self.vuln_results_text.insert(tk.END, f"URL: {results.get('url', 'N/A')}\n")
                self.vuln_results_text.insert(tk.END, f"Timestamp: {results.get('timestamp', 'N/A')}\n")
                self.vuln_results_text.insert(tk.END, f"Total Tests: {results.get('total_tests', 0)}\n")
                self.vuln_results_text.insert(tk.END, f"Positive Tests: {results.get('vulnerable_tests', 0)}\n\n")
                
                if results['vulnerabilities']:
                    self.vuln_results_text.insert(tk.END, f"🔴 VULNERABILITIES FOUND:\n")
                    for vuln in results['vulnerabilities']:
                        self.vuln_results_text.insert(tk.END, f"\n• Type: {vuln['type']}\n")
                        self.vuln_results_text.insert(tk.END, f"  Payload: {vuln['payload']}\n")
                        self.vuln_results_text.insert(tk.END, f"  URL: {vuln['url']}\n")
                        self.vuln_results_text.insert(tk.END, f"  Evidence: {vuln['evidence']}\n")
                else:
                    self.vuln_results_text.insert(tk.END, f"✅ No vulnerabilities detected\n")
                
                # Update statistics
                self.update_statistics('threats_detected', results.get('vulnerable_tests', 0))
                
            except Exception as e:
                self.log_output(f"❌ Vulnerability scan error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def check_ssl(self):
        """Check SSL/TLS certificate"""
        hostname = self.ssl_host_entry.get().strip()
        port_str = self.ssl_port_entry.get().strip()
        
        if not hostname:
            messagebox.showerror("Error", "Please enter a hostname")
            return
        
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number")
            return
        
        def check_thread():
            self.status_label.config(text="🔐 Checking SSL/TLS certificate...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                results = self.tools['ssl_checker'].check_ssl(hostname, port)
                # Display results
                self.ssl_results_text.delete(1.0, tk.END)
                self.ssl_results_text.insert(1.0, f"SSL/TLS CERTIFICATE CHECK\n")
                self.ssl_results_text.insert(tk.END, f"{'='*50}\n\n")
                self.ssl_results_text.insert(tk.END, f"Hostname: {results.get('hostname', 'N/A')}\n")
                self.ssl_results_text.insert(tk.END, f"Port: {results.get('port', 'N/A')}\n")
                self.ssl_results_text.insert(tk.END, f"Timestamp: {results.get('timestamp', 'N/A')}\n")
                self.ssl_results_text.insert(tk.END, f"Valid: {'✅ Yes' if results.get('valid') else '❌ No'}\n\n")
                
                if results.get('valid'):
                    # Certificate details
                    cert = results.get('certificate', {})
                    if 'subject' in cert:
                        self.ssl_results_text.insert(tk.END, f"SUBJECT:\n")
                        for item in cert['subject']:
                            for key, value in item:
                                self.ssl_results_text.insert(tk.END, f"  {key}: {value}\n")
                    
                    if 'issuer' in cert:
                        self.ssl_results_text.insert(tk.END, f"\nISSUER:\n")
                        for item in cert['issuer']:
                            for key, value in item:
                                self.ssl_results_text.insert(tk.END, f"  {key}: {value}\n")
                    
                    if 'notBefore' in cert and 'notAfter' in cert:
                        self.ssl_results_text.insert(tk.END, f"\nVALIDITY:\n")
                        self.ssl_results_text.insert(tk.END, f"  Not Before: {cert['notBefore']}\n")
                        self.ssl_results_text.insert(tk.END, f"  Not After: {cert['notAfter']}\n")
                
                # Cipher information
                if 'cipher' in results:
                    cipher = results['cipher']
                    self.ssl_results_text.insert(tk.END, f"\nCIPHER:\n")
                    self.ssl_results_text.insert(tk.END, f"  Name: {cipher.get('name', 'N/A')}\n")
                    self.ssl_results_text.insert(tk.END, f"  Version: {cipher.get('version', 'N/A')}\n")
                    self.ssl_results_text.insert(tk.END, f"  Bits: {cipher.get('bits', 'N/A')}\n")
                
                # Warnings and errors
                if results.get('warnings'):
                    self.ssl_results_text.insert(tk.END, f"\n⚠️ WARNINGS:\n")
                    for warning in results['warnings']:
                        self.ssl_results_text.insert(tk.END, f"  • {warning}\n")
                
                if results.get('errors'):
                    self.ssl_results_text.insert(tk.END, f"\n❌ ERRORS:\n")
                    for error in results['errors']:
                        self.ssl_results_text.insert(tk.END, f"  • {error}\n")
                
            except Exception as e:
                self.log_output(f"❌ SSL check error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    def check_password_strength(self):
        """Check password strength"""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        def check_thread():
            self.status_label.config(text="🔑 Analyzing password strength...")
            self.progress_bar.pack(side=tk.LEFT, padx=10)
            self.progress_bar.start()
            try:
                results = self.tools['password_checker'].check_password(password)
                # Display results
                self.password_results_text.delete(1.0, tk.END)
                self.password_results_text.insert(1.0, f"PASSWORD STRENGTH ANALYSIS\n")
                self.password_results_text.insert(tk.END, f"{'='*50}\n\n")
                self.password_results_text.insert(tk.END, f"Strength: {results.get('strength', 'N/A')}\n")
                self.password_results_text.insert(tk.END, f"Score: {results.get('score', 0)}/{results.get('max_score', 9)}\n\n")
                
                self.password_results_text.insert(tk.END, f"FEEDBACK:\n")
                for feedback in results.get('feedback', []):
                    self.password_results_text.insert(tk.END, f"  {feedback}\n")
                
                self.password_results_text.insert(tk.END, f"\nCHARACTER ANALYSIS:\n")
                checks = results.get('checks', {})
                for check_name, check_result in checks.items():
                    status = "✅ Present" if check_result else "❌ Missing"
                    self.password_results_text.insert(tk.END, f"  {check_name.title()}: {status}\n")
                
                # Add recommendations
                self.password_results_text.insert(tk.END, f"\n🔒 RECOMMENDATIONS:\n")
                if results['strength'] == 'Weak':
                    self.password_results_text.insert(tk.END, f"  • Use at least 12 characters\n")
                    self.password_results_text.insert(tk.END, f"  • Include uppercase letters\n")
                    self.password_results_text.insert(tk.END, f"  • Include numbers and symbols\n")
                    self.password_results_text.insert(tk.END, f"  • Avoid common passwords\n")
                elif results['strength'] == 'Moderate':
                    self.password_results_text.insert(tk.END, f"  • Increase length to 12+ characters\n")
                    self.password_results_text.insert(tk.END, f"  • Add special characters\n")
                    self.password_results_text.insert(tk.END, f"  • Consider using a passphrase\n")
                else:
                    self.password_results_text.insert(tk.END, f"  • Your password is strong!\n")
                    self.password_results_text.insert(tk.END, f"  • Consider using a password manager\n")
                
            except Exception as e:
                self.log_output(f"❌ Password check error: {str(e)}", "error")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.status_label.config(text="✅ Ready")
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    def generate_password(self):
        """Generate a strong password"""
        import random
        import string
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Generate password with all character types
        password_chars = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # Fill remaining characters randomly
        all_chars = lowercase + uppercase + digits + symbols
        password_chars.extend(random.choice(all_chars) for _ in range(8))
        
        # Shuffle and create password
        random.shuffle(password_chars)
        password = ''.join(password_chars)
        
        # Update entry field
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
        self.log_output("🎲 Generated strong password", "success")
    
    def install_dependency(self, library):
        """Install missing dependency"""
        import subprocess
        import sys
        
        self.log_output(f"📦 Installing {library}...", "info")
        try:
            # Run pip install
            result = subprocess.run([sys.executable, "-m", "pip", "install", library],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.log_output(f"✅ Successfully installed {library}", "success")
                # Update status label
                if library == "requests":
                    self.status_labels["Requests"].config(text="Available")
                elif library == "scapy":
                    self.status_labels["Scapy"].config(text="Available")
                # Reload module
                messagebox.showinfo("Success", 
                                  f"{library} installed successfully!\n"
                                  "Please restart the application.")
            else:
                self.log_output(f"❌ Failed to install {library}: {result.stderr}", "error")
        except Exception as e:
            self.log_output(f"❌ Installation error: {str(e)}", "error")


def main():
    """Main entry point"""
    root = tk.Tk()
    # Set window icon (if available)
    try:
        root.iconbitmap('security.ico')
    except:
        pass
    app = EnhancedSecurityToolkitGUI(root)
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    # Start main loop
    root.mainloop()


if __name__ == "__main__":
    main()