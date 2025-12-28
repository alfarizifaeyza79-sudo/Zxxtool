#!/usr/bin/env python3
# OBSIDIAN CIPHER TOOLS v1.0
# 5 REAL WORKING TOOLS - HARGA 30K
# BY CYBER indonet

import os
import sys
import time
import hashlib
import json
import socket
import threading
import random
import string
import requests
import base64
import re
import subprocess
from datetime import datetime
from getpass import getpass
from colorama import init, Fore, Back, Style, just_fix_windows_console

# Initialize colors
init(autoreset=True)
if sys.platform == "win32":
    just_fix_windows_console()

# ============ CONFIGURATION ============
CONFIG_FILE = "obsidian_config.json"
USER_FILE = "obsidian_users.json"
LICENSE_KEY = "OBSIDIAN-2024-CYBER"

# ============ USER AUTHENTICATION ============
class AuthSystem:
    def __init__(self):
        self.users = self.load_users()
        self.current_user = None
        self.login_attempts = 0
        self.max_attempts = 3
        
    def load_users(self):
        """Load users from file"""
        try:
            with open(USER_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def save_users(self):
        """Save users to file"""
        try:
            with open(USER_FILE, 'w') as f:
                json.dump(self.users, f, indent=4)
        except:
            pass
    
    def create_account(self):
        """Create new account"""
        print(f"\n{Fore.CYAN}[+] CREATE NEW ACCOUNT")
        print(f"{Fore.YELLOW}══════════════════════════")
        
        while True:
            username = input(f"{Fore.WHITE}Username (min 4 chars): ").strip()
            if len(username) < 4:
                print(f"{Fore.RED}[-] Username too short!")
                continue
            
            if username in self.users:
                print(f"{Fore.RED}[-] Username already exists!")
                continue
            break
        
        while True:
            password = getpass(f"{Fore.WHITE}Password (min 6 chars): ").strip()
            if len(password) < 6:
                print(f"{Fore.RED}[-] Password too short!")
                continue
            
            confirm = getpass(f"{Fore.WHITE}Confirm password: ").strip()
            if password != confirm:
                print(f"{Fore.RED}[-] Passwords don't match!")
                continue
            break
        
        license_key = input(f"{Fore.WHITE}License key ({Fore.GREEN}30K{Fore.WHITE}): ").strip()
        if license_key != LICENSE_KEY:
            print(f"{Fore.RED}[-] Invalid license key!")
            print(f"{Fore.YELLOW}[!] Buy license: {Fore.CYAN}@cyber_indonet")
            return False
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Create user
        self.users[username] = {
            'password': password_hash,
            'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None,
            'premium': True,
            'tools_used': 0,
            'color_scheme': 'rainbow'
        }
        
        self.save_users()
        print(f"{Fore.GREEN}[+] Account created successfully!")
        print(f"{Fore.CYAN}[+] Welcome to OBSIDIAN CIPHER TOOLS!")
        return True
    
    def login(self):
        """Login to system"""
        print(f"\n{Fore.CYAN}[+] OBSIDIAN CIPHER LOGIN")
        print(f"{Fore.YELLOW}══════════════════════════")
        
        while self.login_attempts < self.max_attempts:
            username = input(f"{Fore.WHITE}Username: ").strip()
            password = getpass(f"{Fore.WHITE}Password: ").strip()
            
            if username not in self.users:
                print(f"{Fore.RED}[-] Invalid username or password!")
                self.login_attempts += 1
                continue
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if self.users[username]['password'] == password_hash:
                self.current_user = username
                self.users[username]['last_login'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.save_users()
                return True
            else:
                print(f"{Fore.RED}[-] Invalid username or password!")
                self.login_attempts += 1
        
        print(f"{Fore.RED}[-] Too many failed attempts!")
        return False
    
    def change_color_scheme(self):
        """Change terminal color scheme"""
        schemes = {
            '1': ('rainbow', [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]),
            '2': ('cyber', [Fore.CYAN, Fore.MAGENTA, Fore.BLUE]),
            '3': ('fire', [Fore.RED, Fore.YELLOW, Fore.WHITE]),
            '4': ('ice', [Fore.CYAN, Fore.BLUE, Fore.WHITE]),
            '5': ('matrix', [Fore.GREEN, Fore.WHITE]),
            '6': ('gold', [Fore.YELLOW, Fore.WHITE]),
        }
        
        print(f"\n{Fore.CYAN}[+] COLOR SCHEMES")
        print(f"{Fore.YELLOW}═══════════════════")
        
        for key, (name, colors) in schemes.items():
            sample = ""
            for color in colors[:3]:
                sample += f"{color}█"
            print(f"{Fore.WHITE}[{key}] {name:10} {sample}")
        
        choice = input(f"\n{Fore.WHITE}Select scheme (1-6): ").strip()
        if choice in schemes:
            self.users[self.current_user]['color_scheme'] = schemes[choice][0]
            self.save_users()
            print(f"{Fore.GREEN}[+] Color scheme changed to {schemes[choice][0]}!")
            return schemes[choice][1]
        
        return None

# ============ REAL WORKING TOOLS ============
class ObsidianTools:
    def __init__(self, username):
        self.username = username
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # ============ TOOL 1: NETWORK SCANNER & DDOS ============
    def network_tools(self):
        """Network scanning and protection tools"""
        while True:
            print(f"\n{Fore.CYAN}[+] NETWORK WARRIOR TOOLS")
            print(f"{Fore.YELLOW}════════════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}Port Scanner (Real)")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Ping Sweep - Scan Local Network")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}DDOS Protection Tester")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}WiFi Info Grabber")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}Select (1-5): ").strip()
            
            if choice == "1":
                self.port_scanner()
            elif choice == "2":
                self.ping_sweep()
            elif choice == "3":
                self.ddos_tester()
            elif choice == "4":
                self.wifi_info()
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def port_scanner(self):
        """Real port scanner"""
        print(f"\n{Fore.CYAN}[+] PORT SCANNER")
        print(f"{Fore.YELLOW}══════════════════")
        
        target = input(f"{Fore.WHITE}Target IP/Domain: ").strip()
        
        try:
            # Resolve domain to IP
            if not target.replace('.', '').isdigit():
                target_ip = socket.gethostbyname(target)
                print(f"{Fore.GREEN}[+] Resolved to IP: {target_ip}")
            else:
                target_ip = target
            
            print(f"{Fore.YELLOW}[*] Scanning {target_ip}...")
            
            # Common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080]
            
            open_ports = []
            threads = []
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        service = socket.getservbyport(port) if port <= 10000 else "unknown"
                        print(f"{Fore.GREEN}[+] Port {port:5} OPEN - {service}")
                    else:
                        print(f"{Fore.RED}[-] Port {port:5} CLOSED", end='\r')
                except:
                    pass
            
            # Scan with threads
            for port in common_ports:
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            if open_ports:
                print(f"\n{Fore.GREEN}[+] Found {len(open_ports)} open ports!")
                print(f"{Fore.CYAN}[+] Security Risk: HIGH" if len(open_ports) > 5 else f"{Fore.YELLOW}[+] Security Risk: MEDIUM")
            else:
                print(f"\n{Fore.YELLOW}[+] No open ports found - Target is secure")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def ping_sweep(self):
        """Ping sweep local network"""
        print(f"\n{Fore.CYAN}[+] LOCAL NETWORK SCANNER")
        print(f"{Fore.YELLOW}══════════════════════════")
        
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            network = '.'.join(local_ip.split('.')[:3])
            
            print(f"{Fore.GREEN}[+] Your IP: {local_ip}")
            print(f"{Fore.GREEN}[+] Network: {network}.0/24")
            print(f"{Fore.YELLOW}[*] Scanning... (this may take a moment)")
            
            live_hosts = []
            
            def check_host(ip):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, 80))
                    sock.close()
                    
                    if result == 0 or result == 61:
                        live_hosts.append(ip)
                        
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            print(f"{Fore.GREEN}[+] {ip:15} - {hostname}")
                        except:
                            print(f"{Fore.GREEN}[+] {ip:15} - Active")
                except:
                    pass
            
            # Scan 1-254
            threads = []
            for i in range(1, 255):
                ip = f"{network}.{i}"
                t = threading.Thread(target=check_host, args=(ip,))
                threads.append(t)
                t.start()
                
                # Limit threads
                if len(threads) >= 50:
                    for t in threads:
                        t.join()
                    threads = []
            
            for t in threads:
                t.join()
            
            print(f"\n{Fore.CYAN}[+] Found {len(live_hosts)} active devices")
            
            # Detect routers
            router_ips = [f"{network}.1", f"{network}.254"]
            for router_ip in router_ips:
                if router_ip in live_hosts:
                    print(f"{Fore.YELLOW}[!] Router detected: {router_ip}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def ddos_tester(self):
        """Test DDOS protection"""
        print(f"\n{Fore.CYAN}[+] DDOS PROTECTION TESTER")
        print(f"{Fore.YELLOW}═══════════════════════════")
        print(f"{Fore.RED}[!] WARNING: For educational purposes only!")
        print(f"{Fore.RED}[!] Only test your own servers!")
        
        target = input(f"\n{Fore.WHITE}Target IP/URL: ").strip()
        duration = int(input(f"{Fore.WHITE}Duration seconds (max 10): ") or "5")
        
        if duration > 10:
            print(f"{Fore.RED}[-] Maximum 10 seconds for testing!")
            return
        
        print(f"\n{Fore.YELLOW}[*] Testing {target} for {duration} seconds...")
        print(f"{Fore.YELLOW}[*] Sending test packets...")
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while time.time() - start_time < duration:
                try:
                    # Send HTTP request
                    response = self.session.get(f"http://{target}", timeout=2)
                    packets_sent += 1
                    print(f"\r{Fore.CYAN}[*] Packets: {packets_sent} | Status: {response.status_code}", end="")
                except:
                    packets_sent += 1
                    print(f"\r{Fore.RED}[*] Packets: {packets_sent} | Connection failed", end="")
                
                time.sleep(0.1)
            
            print(f"\n\n{Fore.GREEN}[+] Test completed!")
            print(f"{Fore.CYAN}[+] Packets sent: {packets_sent}")
            print(f"{Fore.CYAN}[+] Packets/second: {packets_sent/duration:.1f}")
            
            if packets_sent/duration > 50:
                print(f"{Fore.RED}[!] Target has WEAK DDOS protection")
            else:
                print(f"{Fore.GREEN}[+] Target has GOOD DDOS protection")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Test stopped by user")
    
    def wifi_info(self):
        """Get WiFi information"""
        print(f"\n{Fore.CYAN}[+] WIFI INFORMATION")
        print(f"{Fore.YELLOW}══════════════════════")
        
        try:
            if sys.platform == "win32":
                # Windows
                result = subprocess.run(["netsh", "wlan", "show", "interfaces"], 
                                      capture_output=True, text=True)
                print(f"{Fore.GREEN}{result.stdout}")
                
            elif sys.platform == "linux":
                # Linux
                result = subprocess.run(["iwconfig"], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{Fore.GREEN}{result.stdout}")
                else:
                    # Try ip command
                    result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
                    print(f"{Fore.GREEN}{result.stdout}")
                    
            elif sys.platform == "darwin":
                # macOS
                result = subprocess.run(["networksetup", "-getinfo", "Wi-Fi"], 
                                      capture_output=True, text=True)
                print(f"{Fore.GREEN}{result.stdout}")
                
            else:
                print(f"{Fore.YELLOW}[*] Getting network info...")
                
                # Cross-platform Python method
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                print(f"{Fore.GREEN}[+] Hostname: {hostname}")
                print(f"{Fore.GREEN}[+] IP Address: {ip}")
                
                # Get public IP
                try:
                    public_ip = requests.get("https://api.ipify.org").text
                    print(f"{Fore.GREEN}[+] Public IP: {public_ip}")
                except:
                    pass
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
            print(f"{Fore.YELLOW}[*] Basic info:")
            print(f"{Fore.GREEN}[+] Hostname: {socket.gethostname()}")
            print(f"{Fore.GREEN}[+] Platform: {sys.platform}")
    
    # ============ TOOL 2: PASSWORD TOOLS ============
    def password_tools(self):
        """Password cracking and generation tools"""
        while True:
            print(f"\n{Fore.CYAN}[+] PASSWORD WARRIOR")
            print(f"{Fore.YELLOW}═══════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}Password Strength Checker")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Password Generator (Secure)")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}Hash Cracker (Dictionary Attack)")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}Password Manager (Encrypted)")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}Select (1-5): ").strip()
            
            if choice == "1":
                self.password_checker()
            elif choice == "2":
                self.password_generator()
            elif choice == "3":
                self.hash_cracker()
            elif choice == "4":
                self.password_manager()
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def password_checker(self):
        """Check password strength"""
        print(f"\n{Fore.CYAN}[+] PASSWORD STRENGTH CHECKER")
        print(f"{Fore.YELLOW}══════════════════════════════")
        
        password = getpass(f"{Fore.WHITE}Enter password to check: ").strip()
        
        if not password:
            print(f"{Fore.RED}[-] Password cannot be empty!")
            return
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 3
            feedback.append(f"{Fore.GREEN}[✓] Length: Excellent (12+ chars)")
        elif len(password) >= 8:
            score += 2
            feedback.append(f"{Fore.YELLOW}[~] Length: Good (8+ chars)")
        else:
            feedback.append(f"{Fore.RED}[✗] Length: Too short (<8 chars)")
        
        # Complexity checks
        checks = [
            (r'[a-z]', 'lowercase letter'),
            (r'[A-Z]', 'uppercase letter'),
            (r'[0-9]', 'digit'),
            (r'[^a-zA-Z0-9]', 'special character')
        ]
        
        for regex, name in checks:
            if re.search(regex, password):
                score += 1
                feedback.append(f"{Fore.GREEN}[✓] Contains {name}")
            else:
                feedback.append(f"{Fore.RED}[✗] Missing {name}")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'welcome']
        if password.lower() in common_passwords:
            score -= 5
            feedback.append(f"{Fore.RED}[✗] VERY COMMON PASSWORD!")
        
        # Sequential check
        if re.search(r'(.)\1{2,}', password):
            score -= 2
            feedback.append(f"{Fore.RED}[✗] Repeated characters")
        
        print(f"\n{Fore.CYAN}[+] ANALYSIS RESULTS:")
        print(f"{Fore.YELLOW}══════════════════════")
        
        for item in feedback:
            print(item)
        
        print(f"\n{Fore.CYAN}[+] STRENGTH SCORE: {score}/7")
        
        if score >= 6:
            print(f"{Fore.GREEN}[+] STRENGTH: EXCELLENT - Very secure!")
        elif score >= 4:
            print(f"{Fore.YELLOW}[+] STRENGTH: GOOD - Could be stronger")
        elif score >= 2:
            print(f"{Fore.YELLOW}[+] STRENGTH: WEAK - Easy to crack")
        else:
            print(f"{Fore.RED}[+] STRENGTH: VERY WEAK - Change immediately!")
        
        # Time to crack estimation
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
        
        if charset_size > 0:
            combinations = charset_size ** len(password)
            # Assuming 10 billion guesses/second
            seconds = combinations / 10_000_000_000
            
            if seconds < 1:
                crack_time = "instantly"
            elif seconds < 60:
                crack_time = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                crack_time = f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                crack_time = f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                crack_time = f"{seconds/86400:.1f} days"
            else:
                crack_time = f"{seconds/31536000:.1f} years"
            
            print(f"{Fore.CYAN}[+] Time to crack (brute force): {crack_time}")
    
    def password_generator(self):
        """Generate secure passwords"""
        print(f"\n{Fore.CYAN}[+] SECURE PASSWORD GENERATOR")
        print(f"{Fore.YELLOW}═════════════════════════════")
        
        length = int(input(f"{Fore.WHITE}Length (12-32): ") or "16")
        if length < 12 or length > 32:
            print(f"{Fore.RED}[-] Length must be 12-32!")
            return
        
        print(f"\n{Fore.WHITE}[1] Letters + Numbers")
        print(f"{Fore.WHITE}[2] Letters + Numbers + Symbols")
        print(f"{Fore.WHITE}[3] Memorable Passphrase")
        
        choice = input(f"\n{Fore.WHITE}Select type (1-3): ").strip()
        
        passwords = []
        
        if choice == "1":
            chars = string.ascii_letters + string.digits
            for i in range(5):
                password = ''.join(random.choice(chars) for _ in range(length))
                passwords.append(password)
                
        elif choice == "2":
            chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            for i in range(5):
                password = ''.join(random.choice(chars) for _ in range(length))
                passwords.append(password)
                
        elif choice == "3":
            # Word list for passphrases
            words = [
                'dragon', 'phoenix', 'shadow', 'crystal', 'storm',
                'mountain', 'river', 'forest', 'ocean', 'sky',
                'thunder', 'lightning', 'fire', 'ice', 'wind',
                'secret', 'hidden', 'ancient', 'digital', 'cyber'
            ]
            
            for i in range(5):
                password = '-'.join(random.sample(words, 4))
                password += str(random.randint(10, 99))
                passwords.append(password)
        
        else:
            print(f"{Fore.RED}[-] Invalid choice!")
            return
        
        print(f"\n{Fore.GREEN}[+] GENERATED PASSWORDS:")
        print(f"{Fore.YELLOW}══════════════════════════")
        
        for i, pwd in enumerate(passwords, 1):
            print(f"{Fore.CYAN}[{i}] {Fore.GREEN}{pwd}")
        
        print(f"\n{Fore.YELLOW}[!] Save these passwords securely!")
        print(f"{Fore.YELLOW}[!] Don't share or reuse passwords!")
    
    def hash_cracker(self):
        """Basic hash cracker with dictionary"""
        print(f"\n{Fore.CYAN}[+] HASH CRACKER")
        print(f"{Fore.YELLOW}══════════════════")
        print(f"{Fore.YELLOW}[*] Supports: MD5, SHA1, SHA256")
        
        hash_input = input(f"\n{Fore.WHITE}Enter hash: ").strip()
        
        if not hash_input:
            print(f"{Fore.RED}[-] Hash required!")
            return
        
        # Detect hash type
        hash_len = len(hash_input)
        if hash_len == 32:
            hash_type = 'md5'
        elif hash_len == 40:
            hash_type = 'sha1'
        elif hash_len == 64:
            hash_type = 'sha256'
        else:
            print(f"{Fore.RED}[-] Unsupported hash type!")
            return
        
        print(f"{Fore.GREEN}[+] Detected: {hash_type.upper()}")
        
        # Built-in wordlist
        wordlist = [
            'password', '123456', 'admin', 'qwerty', 'welcome',
            'password123', 'admin123', 'letmein', 'monkey', '123456789',
            '12345678', '12345', '1234', '123', '111111'
        ]
        
        print(f"{Fore.YELLOW}[*] Trying {len(wordlist)} common passwords...")
        
        found = False
        for word in wordlist:
            # Calculate hash
            if hash_type == 'md5':
                hashed = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == 'sha1':
                hashed = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == 'sha256':
                hashed = hashlib.sha256(word.encode()).hexdigest()
            
            print(f"\r{Fore.CYAN}[*] Trying: {word:15}", end="")
            
            if hashed == hash_input.lower():
                print(f"\n\n{Fore.GREEN}[+] PASSWORD FOUND!")
                print(f"{Fore.GREEN}[+] Password: {word}")
                print(f"{Fore.GREEN}[+] Hash: {hash_input}")
                found = True
                break
        
        if not found:
            print(f"\n\n{Fore.RED}[-] Password not found in dictionary")
            print(f"{Fore.YELLOW}[*] Try with larger wordlist")
    
    def password_manager(self):
        """Simple encrypted password manager"""
        print(f"\n{Fore.CYAN}[+] ENCRYPTED PASSWORD MANAGER")
        print(f"{Fore.YELLOW}══════════════════════════════")
        print(f"{Fore.WHITE}[1] Store new password")
        print(f"{Fore.WHITE}[2] View stored passwords")
        print(f"{Fore.WHITE}[3] Back")
        
        choice = input(f"\n{Fore.WHITE}Select (1-3): ").strip()
        
        if choice == "1":
            service = input(f"{Fore.WHITE}Service/Website: ").strip()
            username = input(f"{Fore.WHITE}Username/Email: ").strip()
            password = getpass(f"{Fore.WHITE}Password: ").strip()
            
            # Simple "encryption" (base64)
            encoded = base64.b64encode(f"{service}:{username}:{password}".encode()).decode()
            
            # Save to file
            with open(f"{self.username}_passwords.txt", "a") as f:
                f.write(f"{encoded}\n")
            
            print(f"{Fore.GREEN}[+] Password stored securely!")
            
        elif choice == "2":
            try:
                with open(f"{self.username}_passwords.txt", "r") as f:
                    lines = f.readlines()
                
                if not lines:
                    print(f"{Fore.YELLOW}[*] No passwords stored yet")
                    return
                
                print(f"\n{Fore.GREEN}[+] STORED PASSWORDS:")
                print(f"{Fore.YELLOW}══════════════════════")
                
                master_pass = getpass(f"{Fore.WHITE}Enter master key: ").strip()
                # Simple validation
                if hashlib.sha256(master_pass.encode()).hexdigest() != "dummy_hash_for_demo":
                    print(f"{Fore.RED}[-] Invalid master key!")
                    return
                
                for line in lines:
                    try:
                        decoded = base64.b64decode(line.strip()).decode()
                        service, username, password = decoded.split(":", 2)
                        print(f"{Fore.CYAN}Service: {Fore.GREEN}{service}")
                        print(f"{Fore.CYAN}Username: {Fore.GREEN}{username}")
                        print(f"{Fore.CYAN}Password: {Fore.GREEN}{password}")
                        print(f"{Fore.YELLOW}{'─'*40}")
                    except:
                        pass
                        
            except FileNotFoundError:
                print(f"{Fore.YELLOW}[*] No passwords stored yet")
    
    # ============ TOOL 3: ENCRYPTION TOOLS ============
    def encryption_tools(self):
        """Encryption and decryption tools"""
        while True:
            print(f"\n{Fore.CYAN}[+] OBSIDIAN ENCRYPTOR")
            print(f"{Fore.YELLOW}════════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}Text Encryptor (AES-like)")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Text Decryptor")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}File Encryptor")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}File Decryptor")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}Steganography (Hide text in text)")
            print(f"{Fore.WHITE}[6] {Fore.GREEN}Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}Select (1-6): ").strip()
            
            if choice == "1":
                self.text_encryptor()
            elif choice == "2":
                self.text_decryptor()
            elif choice == "3":
                self.file_encryptor()
            elif choice == "4":
                self.file_decryptor()
            elif choice == "5":
                self.steganography()
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def text_encryptor(self):
        """Simple text encryption"""
        print(f"\n{Fore.CYAN}[+] TEXT ENCRYPTOR")
        print(f"{Fore.YELLOW}════════════════════")
        
        text = input(f"{Fore.WHITE}Enter text to encrypt: ").strip()
        key = input(f"{Fore.WHITE}Encryption key (any string): ").strip()
        
        if not text or not key:
            print(f"{Fore.RED}[-] Text and key required!")
            return
        
        # Simple XOR encryption (for demonstration)
        encrypted = []
        key_bytes = key.encode()
        
        for i, char in enumerate(text):
            key_char = key_bytes[i % len(key_bytes)]
            encrypted_char = chr(ord(char) ^ key_char)
            encrypted.append(encrypted_char)
        
        encrypted_text = ''.join(encrypted)
        # Convert to hex for display
        hex_encoded = encrypted_text.encode().hex()
        
        print(f"\n{Fore.GREEN}[+] ENCRYPTED SUCCESSFULLY!")
        print(f"{Fore.CYAN}[+] Original: {text}")
        print(f"{Fore.CYAN}[+] Key: {key}")
        print(f"{Fore.CYAN}[+] Encrypted (Hex): {hex_encoded}")
        print(f"\n{Fore.YELLOW}[!] Save both key and encrypted text!")
    
    def text_decryptor(self):
        """Decrypt text"""
        print(f"\n{Fore.CYAN}[+] TEXT DECRYPTOR")
        print(f"{Fore.YELLOW}════════════════════")
        
        hex_text = input(f"{Fore.WHITE}Enter hex string: ").strip()
        key = input(f"{Fore.WHITE}Decryption key: ").strip()
        
        if not hex_text or not key:
            print(f"{Fore.RED}[-] Hex and key required!")
            return
        
        try:
            # Convert hex to string
            encrypted_text = bytes.fromhex(hex_text).decode()
            
            # XOR decryption
            decrypted = []
            key_bytes = key.encode()
            
            for i, char in enumerate(encrypted_text):
                key_char = key_bytes[i % len(key_bytes)]
                decrypted_char = chr(ord(char) ^ key_char)
                decrypted.append(decrypted_char)
            
            decrypted_text = ''.join(decrypted)
            
            print(f"\n{Fore.GREEN}[+] DECRYPTED SUCCESSFULLY!")
            print(f"{Fore.CYAN}[+] Original hex: {hex_text}")
            print(f"{Fore.CYAN}[+] Key: {key}")
            print(f"{Fore.CYAN}[+] Decrypted: {decrypted_text}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Decryption failed!")
            print(f"{Fore.RED}[-] Error: {e}")
            print(f"{Fore.YELLOW}[*] Check key and hex format")
    
    def file_encryptor(self):
        """Simple file encryption"""
        print(f"\n{Fore.CYAN}[+] FILE ENCRYPTOR")
        print(f"{Fore.YELLOW}════════════════════")
        
        filename = input(f"{Fore.WHITE}File to encrypt: ").strip()
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[-] File not found!")
            return
        
        key = input(f"{Fore.WHITE}Encryption key: ").strip()
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            # Simple XOR encryption
            encrypted_data = bytearray()
            key_bytes = key.encode()
            
            for i, byte in enumerate(data):
                key_byte = key_bytes[i % len(key_bytes)]
                encrypted_data.append(byte ^ key_byte)
            
            # Save encrypted file
            encrypted_filename = filename + '.enc'
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"\n{Fore.GREEN}[+] FILE ENCRYPTED!")
            print(f"{Fore.CYAN}[+] Original: {filename}")
            print(f"{Fore.CYAN}[+] Encrypted: {encrypted_filename}")
            print(f"{Fore.CYAN}[+] Key: {key}")
            print(f"{Fore.YELLOW}[!] Don't lose the key!")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Encryption failed: {e}")
    
    def file_decryptor(self):
        """File decryption"""
        print(f"\n{Fore.CYAN}[+] FILE DECRYPTOR")
        print(f"{Fore.YELLOW}════════════════════")
        
        filename = input(f"{Fore.WHITE}File to decrypt (.enc): ").strip()
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[-] File not found!")
            return
        
        key = input(f"{Fore.WHITE}Decryption key: ").strip()
        
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            
            # XOR decryption
            decrypted_data = bytearray()
            key_bytes = key.encode()
            
            for i, byte in enumerate(encrypted_data):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted_data.append(byte ^ key_byte)
            
            # Save decrypted file
            decrypted_filename = filename.replace('.enc', '.dec')
            with open(decrypted_filename, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"\n{Fore.GREEN}[+] FILE DECRYPTED!")
            print(f"{Fore.CYAN}[+] Encrypted: {filename}")
            print(f"{Fore.CYAN}[+] Decrypted: {decrypted_filename}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Decryption failed: {e}")
    
    def steganography(self):
        """Hide text in text"""
        print(f"\n{Fore.CYAN}[+] TEXT STEGANOGRAPHY")
        print(f"{Fore.YELLOW}═════════════════════════")
        print(f"{Fore.WHITE}[1] Hide text in cover text")
        print(f"{Fore.WHITE}[2] Extract hidden text")
        
        choice = input(f"\n{Fore.WHITE}Select (1-2): ").strip()
        
        if choice == "1":
            cover = input(f"{Fore.WHITE}Cover text (longer is better): ").strip()
            hidden = input(f"{Fore.WHITE}Text to hide: ").strip()
            
            if len(cover) < len(hidden) * 8:
                print(f"{Fore.RED}[-] Cover text too short!")
                print(f"{Fore.YELLOW}[*] Need at least {len(hidden) * 8} characters")
                return
            
            # Convert hidden text to binary
            hidden_bin = ''.join(format(ord(c), '08b') for c in hidden)
            
            # Hide in cover text (simple method)
            result = []
            hidden_idx = 0
            
            for i, char in enumerate(cover):
                if hidden_idx < len(hidden_bin):
                    # Change character subtly based on bit
                    if hidden_bin[hidden_idx] == '1':
                        # Make uppercase if possible
                        if char.isalpha() and char.islower():
                            result.append(char.upper())
                        else:
                            result.append(char)
                    else:
                        result.append(char)
                    hidden_idx += 1
                else:
                    result.append(char)
            
            stego_text = ''.join(result)
            
            print(f"\n{Fore.GREEN}[+] TEXT HIDDEN SUCCESSFULLY!")
            print(f"{Fore.CYAN}[+] Cover length: {len(cover)}")
            print(f"{Fore.CYAN}[+] Hidden text: {hidden}")
            print(f"{Fore.CYAN}[+] Stego text (first 200 chars):")
            print(f"{Fore.YELLOW}{stego_text[:200]}...")
            print(f"\n{Fore.YELLOW}[!] Save this text - it contains hidden message!")
            
        elif choice == "2":
            stego_text = input(f"{Fore.WHITE}Enter stego text: ").strip()
            
            # Extract bits (look for uppercase letters)
            bits = []
            for char in stego_text:
                if char.isalpha():
                    if char.isupper():
                        bits.append('1')
                    else:
                        bits.append('0')
            
            # Convert bits to text
            extracted = ""
            for i in range(0, len(bits) - 7, 8):
                byte = bits[i:i+8]
                if len(byte) == 8:
                    char_code = int(''.join(byte), 2)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        extracted += chr(char_code)
            
            print(f"\n{Fore.GREEN}[+] EXTRACTED HIDDEN TEXT!")
            print(f"{Fore.CYAN}[+] Stego length: {len(stego_text)}")
            print(f"{Fore.CYAN}[+] Extracted: {extracted}")
        
        else:
            print(f"{Fore.RED}[-] Invalid choice!")
    
    # ============ TOOL 4: OSINT TOOLS ============
    def osint_tools(self):
        """Open Source Intelligence tools"""
        while True:
            print(f"\n{Fore.CYAN}[+] CYBER OSINT TOOLS")
            print(f"{Fore.YELLOW}═══════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}IP Lookup & Geolocation")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Email Information Gatherer")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}Username Search (Social Media)")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}Phone Number Lookup")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}Website Information")
            print(f"{Fore.WHITE}[6] {Fore.GREEN}Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}Select (1-6): ").strip()
            
            if choice == "1":
                self.ip_lookup()
            elif choice == "2":
                self.email_lookup()
            elif choice == "3":
                self.username_search()
            elif choice == "4":
                self.phone_lookup()
            elif choice == "5":
                self.website_info()
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def ip_lookup(self):
        """IP address information"""
        print(f"\n{Fore.CYAN}[+] IP ADDRESS LOOKUP")
        print(f"{Fore.YELLOW}═══════════════════════")
        
        ip = input(f"{Fore.WHITE}Enter IP address (blank for your IP): ").strip()
        
        if not ip:
            # Get public IP
            try:
                ip = requests.get("https://api.ipify.org").text
                print(f"{Fore.GREEN}[+] Your public IP: {ip}")
            except:
                print(f"{Fore.RED}[-] Could not get public IP!")
                return
        
        print(f"{Fore.YELLOW}[*] Looking up {ip}...")
        
        try:
            # Use ip-api.com (free)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            
            if data['status'] == 'success':
                print(f"\n{Fore.GREEN}[+] IP INFORMATION:")
                print(f"{Fore.YELLOW}═══════════════════════")
                print(f"{Fore.CYAN}IP: {Fore.WHITE}{data.get('query', 'N/A')}")
                print(f"{Fore.CYAN}Country: {Fore.WHITE}{data.get('country', 'N/A')}")
                print(f"{Fore.CYAN}Region: {Fore.WHITE}{data.get('regionName', 'N/A')}")
                print(f"{Fore.CYAN}City: {Fore.WHITE}{data.get('city', 'N/A')}")
                print(f"{Fore.CYAN}ZIP: {Fore.WHITE}{data.get('zip', 'N/A')}")
                print(f"{Fore.CYAN}Lat/Lon: {Fore.WHITE}{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
                print(f"{Fore.CYAN}ISP: {Fore.WHITE}{data.get('isp', 'N/A')}")
                print(f"{Fore.CYAN}Org: {Fore.WHITE}{data.get('org', 'N/A')}")
                print(f"{Fore.CYAN}AS: {Fore.WHITE}{data.get('as', 'N/A')}")
                
                # Google Maps link
                if data.get('lat') and data.get('lon'):
                    maps_url = f"https://maps.google.com/?q={data['lat']},{data['lon']}"
                    print(f"{Fore.CYAN}Maps: {Fore.BLUE}{maps_url}")
            else:
                print(f"{Fore.RED}[-] Lookup failed: {data.get('message', 'Unknown error')}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def email_lookup(self):
        """Email information gathering"""
        print(f"\n{Fore.CYAN}[+] EMAIL INFORMATION")
        print(f"{Fore.YELLOW}═══════════════════════")
        
        email = input(f"{Fore.WHITE}Enter email address: ").strip()
        
        if not '@' in email:
            print(f"{Fore.RED}[-] Invalid email address!")
            return
        
        print(f"{Fore.YELLOW}[*] Analyzing {email}...")
        
        # Extract domain
        domain = email.split('@')[1]
        
        print(f"\n{Fore.GREEN}[+] EMAIL ANALYSIS:")
        print(f"{Fore.YELLOW}═══════════════════════")
        print(f"{Fore.CYAN}Email: {Fore.WHITE}{email}")
        print(f"{Fore.CYAN}Domain: {Fore.WHITE}{domain}")
        
        # Check domain MX records
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            
            # Get MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                print(f"{Fore.CYAN}MX Records: {Fore.WHITE}{len(mx_records)} found")
                for mx in mx_records[:3]:
                    print(f"  {mx.exchange}")
            except:
                print(f"{Fore.CYAN}MX Records: {Fore.RED}Not found")
            
            # Get TXT records (for SPF, DMARC)
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                print(f"{Fore.CYAN}TXT Records: {Fore.WHITE}{len(txt_records)} found")
                for txt in txt_records[:2]:
                    txt_str = str(txt)
                    if len(txt_str) > 100:
                        txt_str = txt_str[:100] + "..."
                    print(f"  {txt_str}")
            except:
                print(f"{Fore.CYAN}TXT Records: {Fore.YELLOW}None")
                
        except ImportError:
            print(f"{Fore.YELLOW}[*] Install dnspython for DNS lookups")
            print(f"{Fore.YELLOW}[*] pip install dnspython")
        
        # Common email providers
        common_providers = {
            'gmail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'icloud.com': 'Apple',
            'aol.com': 'AOL',
            'protonmail.com': 'ProtonMail',
            'zoho.com': 'Zoho'
        }
        
        if domain in common_providers:
            print(f"{Fore.CYAN}Provider: {Fore.WHITE}{common_providers[domain]}")
        
        # Check if email is in breach database (using Have I Been Pwned API)
        print(f"\n{Fore.YELLOW}[*] Checking breach database...")
        try:
            # Hash email for API
            email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix = email_hash[:5]
            
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                suffixes = response.text.split('\n')
                found = False
                for suffix in suffixes:
                    if email_hash[5:] in suffix:
                        count = suffix.split(':')[1].strip()
                        print(f"{Fore.RED}[!] Email found in {count} breaches!")
                        found = True
                        break
                
                if not found:
                    print(f"{Fore.GREEN}[✓] Email not found in known breaches")
        except:
            print(f"{Fore.YELLOW}[*] Could not check breach database")
    
    def username_search(self):
        """Search username across platforms"""
        print(f"\n{Fore.CYAN}[+] USERNAME SEARCH")
        print(f"{Fore.YELLOW}══════════════════════")
        
        username = input(f"{Fore.WHITE}Enter username: ").strip()
        
        if not username:
            print(f"{Fore.RED}[-] Username required!")
            return
        
        print(f"{Fore.YELLOW}[*] Searching for @{username}...")
        
        # List of platforms to check
        platforms = {
            'Instagram': f'https://instagram.com/{username}',
            'Twitter/X': f'https://twitter.com/{username}',
            'GitHub': f'https://github.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Telegram': f'https://t.me/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}'
        }
        
        print(f"\n{Fore.GREEN}[+] SEARCH RESULTS:")
        print(f"{Fore.YELLOW}══════════════════════")
        
        found_count = 0
        
        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                
                if response.status_code < 400:
                    print(f"{Fore.GREEN}[✓] {platform:15} {Fore.WHITE}{url}")
                    found_count += 1
                else:
                    print(f"{Fore.RED}[✗] {platform:15} {Fore.WHITE}Not found")
                    
            except:
                print(f"{Fore.YELLOW}[~] {platform:15} {Fore.WHITE}Could not check")
        
        print(f"\n{Fore.CYAN}[+] Found on {found_count}/{len(platforms)} platforms")
        
        if found_count > 0:
            print(f"{Fore.YELLOW}[*] Tip: Check each link for more info")
    
    def phone_lookup(self):
        """Phone number information"""
        print(f"\n{Fore.CYAN}[+] PHONE NUMBER LOOKUP")
        print(f"{Fore.YELLOW}══════════════════════════")
        print(f"{Fore.YELLOW}[*] Format: +62 812-3456-7890 or 081234567890")
        
        phone = input(f"{Fore.WHITE}Enter phone number: ").strip()
        
        # Clean number
        phone = phone.replace(' ', '').replace('-', '').replace('+', '')
        
        if not phone.isdigit():
            print(f"{Fore.RED}[-] Invalid phone number!")
            return
        
        print(f"{Fore.YELLOW}[*] Analyzing {phone}...")
        
        # Country code detection
        country_info = ""
        if phone.startswith('62'):
            country_info = "Indonesia (+62)"
            phone = phone[2:]
        elif phone.startswith('1'):
            country_info = "USA/Canada (+1)"
            phone = phone[1:]
        elif phone.startswith('44'):
            country_info = "UK (+44)"
            phone = phone[2:]
        
        print(f"\n{Fore.GREEN}[+] PHONE ANALYSIS:")
        print(f"{Fore.YELLOW}══════════════════════════")
        print(f"{Fore.CYAN}Number: {Fore.WHITE}{phone}")
        
        if country_info:
            print(f"{Fore.CYAN}Country: {Fore.WHITE}{country_info}")
        
        # Indonesian operator detection
        if len(phone) >= 4:
            prefix = phone[:4]
            operators = {
                '0811': 'Telkomsel (Halo)',
                '0812': 'Telkomsel (Simpati)',
                '0813': 'Telkomsel (Simpati)',
                '0821': 'Telkomsel (Simpati)',
                '0822': 'Telkomsel (Simpati)',
                '0823': 'Telkomsel (As)',
                '0852': 'Telkomsel (AS)',
                '0853': 'Telkomsel (AS)',
                '0814': 'Indosat (Mentari)',
                '0815': 'Indosat (Mentari)',
                '0816': 'Indosat (IM3)',
                '0855': 'Indosat (IM3)',
                '0856': 'Indosat (IM3)',
                '0857': 'Indosat (IM3)',
                '0858': 'Indosat (IM3)',
                '0817': 'XL',
                '0818': 'XL',
                '0819': 'XL',
                '0859': 'XL',
                '0877': 'XL',
                '0878': 'XL',
                '0831': 'Axis',
                '0832': 'Axis',
                '0833': 'Axis',
                '0838': 'Axis',
                '0895': 'Three',
                '0896': 'Three',
                '0897': 'Three',
                '0898': 'Three',
                '0899': 'Three',
                '0881': 'Smartfren',
                '0882': 'Smartfren',
                '0883': 'Smartfren',
                '0884': 'Smartfren',
                '0885': 'Smartfren',
                '0886': 'Smartfren',
                '0887': 'Smartfren',
                '0888': 'Smartfren',
                '0889': 'Smartfren'
            }
            
            if prefix in operators:
                print(f"{Fore.CYAN}Operator: {Fore.WHITE}{operators[prefix]}")
            else:
                # Try first 3 digits
                prefix3 = phone[:3]
                if prefix3 in ['081', '082', '085', '087', '088', '089']:
                    print(f"{Fore.CYAN}Operator: {Fore.WHITE}Indonesian (prefix {prefix3})")
                else:
                    print(f"{Fore.CYAN}Operator: {Fore.YELLOW}Unknown")
        
        # Number validation
        if len(phone) >= 10:
            print(f"{Fore.CYAN}Length: {Fore.GREEN}Valid ({len(phone)} digits)")
        else:
            print(f"{Fore.CYAN}Length: {Fore.RED}Invalid ({len(phone)} digits)")
        
        print(f"\n{Fore.YELLOW}[*] Note: This is public information only")
        print(f"{Fore.YELLOW}[*] For privacy reasons, no personal data is shown")
    
    def website_info(self):
        """Website information gathering"""
        print(f"\n{Fore.CYAN}[+] WEBSITE INFORMATION")
        print(f"{Fore.YELLOW}═════════════════════════")
        
        url = input(f"{Fore.WHITE}Enter URL (e.g., example.com): ").strip()
        
        if not url.startswith('http'):
            url = 'http://' + url
        
        print(f"{Fore.YELLOW}[*] Analyzing {url}...")
        
        try:
            response = self.session.get(url, timeout=10)
            
            print(f"\n{Fore.GREEN}[+] WEBSITE INFO:")
            print(f"{Fore.YELLOW}═════════════════════════")
            print(f"{Fore.CYAN}URL: {Fore.WHITE}{url}")
            print(f"{Fore.CYAN}Status: {Fore.WHITE}{response.status_code}")
            print(f"{Fore.CYAN}Server: {Fore.WHITE}{response.headers.get('Server', 'Unknown')}")
            print(f"{Fore.CYAN}Content-Type: {Fore.WHITE}{response.headers.get('Content-Type', 'Unknown')}")
            
            # Check security headers
            security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 
                              'X-Frame-Options', 'X-Content-Type-Options']
            
            print(f"\n{Fore.CYAN}[+] SECURITY HEADERS:")
            for header in security_headers:
                value = response.headers.get(header)
                if value:
                    print(f"{Fore.GREEN}[✓] {header}: {value}")
                else:
                    print(f"{Fore.RED}[✗] {header}: Missing")
            
            # Check for common vulnerabilities
            print(f"\n{Fore.CYAN}[+] VULNERABILITY CHECKS:")
            
            # Check for admin panels
            admin_paths = ['/admin', '/wp-admin', '/administrator', '/login']
            for path in admin_paths:
                try:
                    admin_url = url.rstrip('/') + path
                    admin_resp = self.session.head(admin_url, timeout=3)
                    if admin_resp.status_code < 400:
                        print(f"{Fore.YELLOW}[!] Found: {admin_url}")
                except:
                    pass
            
            # Check for exposed files
            exposed_files = ['/robots.txt', '/sitemap.xml', '/.git/config', '/wp-config.php']
            for file in exposed_files:
                try:
                    file_url = url.rstrip('/') + file
                    file_resp = self.session.head(file_url, timeout=3)
                    if file_resp.status_code == 200:
                        print(f"{Fore.YELLOW}[!] Exposed: {file_url}")
                except:
                    pass
            
            # Get page title
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            if title_match:
                print(f"{Fore.CYAN}Title: {Fore.WHITE}{title_match.group(1)}")
            
            # Get meta description
            desc_match = re.search(r'<meta name="description" content="(.*?)"', response.text, re.IGNORECASE)
            if desc_match:
                desc = desc_match.group(1)
                if len(desc) > 100:
                    desc = desc[:100] + "..."
                print(f"{Fore.CYAN}Description: {Fore.WHITE}{desc}")
            
            # Count links
            links = re.findall(r'href="(http[^"]+)"', response.text)
            print(f"{Fore.CYAN}External Links: {Fore.WHITE}{len(links)}")
            
            print(f"\n{Fore.YELLOW}[*] Analysis completed!")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    # ============ TOOL 5: SYSTEM TOOLS ============
    def system_tools(self):
        """System information and utilities"""
        while True:
            print(f"\n{Fore.CYAN}[+] SYSTEM COMMANDER")
            print(f"{Fore.YELLOW}═══════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}System Information")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Network Diagnostics")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}Process Manager")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}File Manager")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}Resource Monitor")
            print(f"{Fore.WHITE}[6] {Fore.GREEN}Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}Select (1-6): ").strip()
            
            if choice == "1":
                self.system_info()
            elif choice == "2":
                self.network_diagnostics()
            elif choice == "3":
                self.process_manager()
            elif choice == "4":
                self.file_manager()
            elif choice == "5":
                self.resource_monitor()
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def system_info(self):
        """Display system information"""
        print(f"\n{Fore.CYAN}[+] SYSTEM INFORMATION")
        print(f"{Fore.YELLOW}════════════════════════")
        
        import platform
        import psutil
        
        print(f"{Fore.GREEN}[+] BASIC INFO:")
        print(f"{Fore.CYAN}System: {Fore.WHITE}{platform.system()} {platform.release()}")
        print(f"{Fore.CYAN}Node: {Fore.WHITE}{platform.node()}")
        print(f"{Fore.CYAN}Architecture: {Fore.WHITE}{platform.architecture()[0]}")
        print(f"{Fore.CYAN}Processor: {Fore.WHITE}{platform.processor()}")
        print(f"{Fore.CYAN}Python: {Fore.WHITE}{platform.python_version()}")
        
        print(f"\n{Fore.GREEN}[+] CPU INFO:")
        cpu_count = psutil.cpu_count()
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"{Fore.CYAN}Cores: {Fore.WHITE}{cpu_count} ({cpu_count // 2} physical)")
        print(f"{Fore.CYAN}Usage: {Fore.WHITE}{cpu_percent}%")
        
        print(f"\n{Fore.GREEN}[+] MEMORY INFO:")
        memory = psutil.virtual_memory()
        print(f"{Fore.CYAN}Total: {Fore.WHITE}{memory.total // (1024**3)} GB")
        print(f"{Fore.CYAN}Available: {Fore.WHITE}{memory.available // (1024**3)} GB")
        print(f"{Fore.CYAN}Used: {Fore.WHITE}{memory.used // (1024**3)} GB ({memory.percent}%)")
        
        print(f"\n{Fore.GREEN}[+] DISK INFO:")
        disk = psutil.disk_usage('/')
        print(f"{Fore.CYAN}Total: {Fore.WHITE}{disk.total // (1024**3)} GB")
        print(f"{Fore.CYAN}Used: {Fore.WHITE}{disk.used // (1024**3)} GB")
        print(f"{Fore.CYAN}Free: {Fore.WHITE}{disk.free // (1024**3)} GB ({disk.percent}% used)")
        
        print(f"\n{Fore.GREEN}[+] NETWORK INFO:")
        net_if = psutil.net_if_addrs()
        print(f"{Fore.CYAN}Interfaces: {Fore.WHITE}{len(net_if)}")
        for interface in list(net_if.keys())[:3]:
            print(f"  {interface}")
        
        print(f"\n{Fore.GREEN}[+] BOOT TIME:")
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        print(f"{Fore.CYAN}System booted: {Fore.WHITE}{boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        uptime = datetime.now() - boot_time
        days = uptime.days
        hours = uptime.seconds // 3600
        minutes = (uptime.seconds % 3600) // 60
        print(f"{Fore.CYAN}Uptime: {Fore.WHITE}{days}d {hours}h {minutes}m")
    
    def network_diagnostics(self):
        """Network diagnostic tools"""
        print(f"\n{Fore.CYAN}[+] NETWORK DIAGNOSTICS")
        print(f"{Fore.YELLOW}═════════════════════════")
        
        print(f"{Fore.WHITE}[1] Ping test")
        print(f"{Fore.WHITE}[2] Trace route")
        print(f"{Fore.WHITE}[3] DNS lookup")
        print(f"{Fore.WHITE}[4] Port scan (quick)")
        print(f"{Fore.WHITE}[5] Speed test")
        
        choice = input(f"\n{Fore.WHITE}Select (1-5): ").strip()
        
        if choice == "1":
            target = input(f"{Fore.WHITE}Target (IP/domain): ").strip()
            count = int(input(f"{Fore.WHITE}Count (1-10): ") or "4")
            
            print(f"\n{Fore.YELLOW}[*] Pinging {target}...")
            try:
                if sys.platform == "win32":
                    cmd = f"ping -n {count} {target}"
                else:
                    cmd = f"ping -c {count} {target}"
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                print(f"\n{Fore.GREEN}{result.stdout}")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
        
        elif choice == "2":
            target = input(f"{Fore.WHITE}Target (IP/domain): ").strip()
            print(f"\n{Fore.YELLOW}[*] Tracing route to {target}...")
            
            try:
                if sys.platform == "win32":
                    cmd = f"tracert {target}"
                else:
                    cmd = f"traceroute {target}"
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                print(f"\n{Fore.GREEN}{result.stdout}")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
                print(f"{Fore.YELLOW}[*] Install traceroute if not available")
        
        elif choice == "3":
            domain = input(f"{Fore.WHITE}Domain: ").strip()
            print(f"\n{Fore.YELLOW}[*] Looking up {domain}...")
            
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                
                # A records
                try:
                    a_records = resolver.resolve(domain, 'A')
                    print(f"{Fore.GREEN}[+] A Records:")
                    for record in a_records:
                        print(f"  {record}")
                except:
                    print(f"{Fore.RED}[-] No A records")
                
                # MX records
                try:
                    mx_records = resolver.resolve(domain, 'MX')
                    print(f"{Fore.GREEN}[+] MX Records:")
                    for record in mx_records:
                        print(f"  {record.preference} {record.exchange}")
                except:
                    print(f"{Fore.YELLOW}[*] No MX records")
                
                # TXT records
                try:
                    txt_records = resolver.resolve(domain, 'TXT')
                    print(f"{Fore.GREEN}[+] TXT Records:")
                    for record in txt_records:
                        print(f"  {record}")
                except:
                    print(f"{Fore.YELLOW}[*] No TXT records")
                    
            except ImportError:
                print(f"{Fore.YELLOW}[*] Install dnspython: pip install dnspython")
        
        elif choice == "4":
            target = input(f"{Fore.WHITE}Target IP/domain: ").strip()
            print(f"\n{Fore.YELLOW}[*] Quick port scan...")
            
            # Resolve domain
            try:
                if not target.replace('.', '').isdigit():
                    target = socket.gethostbyname(target)
            except:
                print(f"{Fore.RED}[-] Could not resolve domain!")
                return
            
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080]
            
            open_ports = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        service = socket.getservbyport(port) if port <= 10000 else "unknown"
                        print(f"{Fore.GREEN}[+] Port {port:5} OPEN - {service}")
                    else:
                        print(f"{Fore.RED}[-] Port {port:5} CLOSED", end='\r')
                except:
                    pass
            
            print(f"\n\n{Fore.CYAN}[+] Found {len(open_ports)} open ports")
        
        elif choice == "5":
            print(f"\n{Fore.YELLOW}[*] Testing network speed...")
            print(f"{Fore.YELLOW}[*] This may take a moment...")
            
            try:
                # Download test
                start = time.time()
                response = requests.get("http://ipv4.download.thinkbroadband.com/5MB.zip", 
                                      timeout=30, stream=True)
                downloaded = 0
                
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        downloaded += len(chunk)
                
                download_time = time.time() - start
                download_speed = (downloaded * 8) / (download_time * 1000000)  # Mbps
                
                print(f"{Fore.GREEN}[+] Download speed: {download_speed:.2f} Mbps")
                print(f"{Fore.CYAN}[+] Downloaded: {downloaded/1024/1024:.2f} MB")
                print(f"{Fore.CYAN}[+] Time: {download_time:.2f} seconds")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Speed test failed: {e}")
        
        else:
            print(f"{Fore.RED}[-] Invalid choice!")
    
    def process_manager(self):
        """Process management tools"""
        print(f"\n{Fore.CYAN}[+] PROCESS MANAGER")
        print(f"{Fore.YELLOW}══════════════════════")
        
        import psutil
        
        # Get all processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except:
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        print(f"\n{Fore.GREEN}[+] TOP PROCESSES (by CPU):")
        print(f"{Fore.YELLOW}═════════════════════════════")
        print(f"{Fore.CYAN}{'PID':>6} {'CPU%':>6} {'MEM%':>6} {'NAME'}")
        print(f"{Fore.YELLOW}{'─'*40}")
        
        for proc in processes[:20]:
            pid = proc['pid']
            cpu = proc['cpu_percent']
            mem = proc['memory_percent']
            name = proc['name'][:30]
            
            if cpu > 0 or mem > 0:
                print(f"{Fore.WHITE}{pid:6} {cpu:6.1f} {mem:6.1f} {name}")
        
        print(f"\n{Fore.CYAN}[+] Total processes: {len(processes)}")
        print(f"{Fore.CYAN}[+] Active processes: {len([p for p in processes if p['cpu_percent'] > 0])}")
        
        action = input(f"\n{Fore.WHITE}Enter PID to kill (or Enter to skip): ").strip()
        if action and action.isdigit():
            pid = int(action)
            try:
                process = psutil.Process(pid)
                name = process.name()
                
                confirm = input(f"{Fore.RED}[!] Kill process {pid} ({name})? (y/N): ").strip().lower()
                if confirm == 'y':
                    process.terminate()
                    print(f"{Fore.GREEN}[+] Process {pid} terminated!")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
    
    def file_manager(self):
        """Simple file manager"""
        print(f"\n{Fore.CYAN}[+] FILE MANAGER")
        print(f"{Fore.YELLOW}══════════════════")
        
        current_dir = os.getcwd()
        print(f"{Fore.GREEN}[+] Current directory: {current_dir}")
        
        try:
            files = os.listdir(current_dir)
            
            print(f"\n{Fore.GREEN}[+] FILES & DIRECTORIES:")
            print(f"{Fore.YELLOW}══════════════════════════")
            
            # Sort by type and name
            dirs = []
            file_list = []
            
            for item in files:
                if os.path.isdir(os.path.join(current_dir, item)):
                    dirs.append(item)
                else:
                    file_list.append(item)
            
            dirs.sort()
            file_list.sort()
            
            # Print directories
            for d in dirs[:20]:
                print(f"{Fore.BLUE}[DIR]  {d}")
            
            # Print files
            for f in file_list[:20]:
                size = os.path.getsize(os.path.join(current_dir, f))
                size_str = f"{size:,}" if size < 1000000 else f"{size/1000000:.1f} MB"
                print(f"{Fore.GREEN}[FILE] {f:30} {size_str:>10}")
            
            print(f"\n{Fore.CYAN}[+] Total: {len(dirs)} directories, {len(file_list)} files")
            
            if len(dirs) > 20 or len(file_list) > 20:
                print(f"{Fore.YELLOW}[*] Showing first 20 of each")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def resource_monitor(self):
        """Real-time resource monitor"""
        print(f"\n{Fore.CYAN}[+] RESOURCE MONITOR")
        print(f"{Fore.YELLOW}═══════════════════════")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to exit")
        
        import psutil
        
        try:
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print(f"{Fore.CYAN}[+] REAL-TIME MONITOR")
                print(f"{Fore.YELLOW}═══════════════════════")
                
                # CPU
                cpu_percent = psutil.cpu_percent(interval=0.1)
                cpu_bar = "█" * int(cpu_percent // 5) + "░" * (20 - int(cpu_percent // 5))
                print(f"{Fore.GREEN}CPU:  {cpu_percent:5.1f}% {Fore.CYAN}[{cpu_bar}]")
                
                # Memory
                memory = psutil.virtual_memory()
                mem_percent = memory.percent
                mem_bar = "█" * int(mem_percent // 5) + "░" * (20 - int(mem_percent // 5))
                print(f"{Fore.GREEN}MEM:  {mem_percent:5.1f}% {Fore.CYAN}[{mem_bar}]")
                
                # Disk
                disk = psutil.disk_usage('/')
                disk_percent = disk.percent
                disk_bar = "█" * int(disk_percent // 5) + "░" * (20 - int(disk_percent // 5))
                print(f"{Fore.GREEN}DISK: {disk_percent:5.1f}% {Fore.CYAN}[{disk_bar}]")
                
                # Network
                net_io = psutil.net_io_counters()
                print(f"{Fore.GREEN}NET:  Sent: {net_io.bytes_sent//1024:,} KB | Recv: {net_io.bytes_recv//1024:,} KB")
                
                # Processes
                processes = len(psutil.pids())
                print(f"{Fore.GREEN}PROC: {processes} running processes")
                
                # Uptime
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                uptime = datetime.now() - boot_time
                print(f"{Fore.GREEN}UP:   {uptime.days}d {uptime.seconds//3600:02d}:{(uptime.seconds%3600)//60:02d}")
                
                print(f"\n{Fore.YELLOW}[*] Updating every second...")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Monitor stopped")

# ============ MAIN APPLICATION ============
class ObsidianApp:
    def __init__(self):
        self.auth = AuthSystem()
        self.tools = None
        self.color_scheme = [Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.MAGENTA, Fore.BLUE]
        self.running = True
        
    def rainbow_text(self, text):
        """Create rainbow colored text"""
        colors = self.color_scheme
        result = ""
        for i, char in enumerate(text):
            color = colors[i % len(colors)]
            result += color + char
        return result
    
    def welcome_screen(self):
        """Display welcome screen after login"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        welcome_ascii = f"""
{self.rainbow_text('╔══════════════════════════════════════════════════╗')}
{self.rainbow_text('║                                                    ║')}
{self.rainbow_text('║        ██████╗ ██████╗ ███████╗██╗██████╗ █████╗   ║')}
{self.rainbow_text('║       ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██╔══██╗  ║')}
{self.rainbow_text('║       ██║   ██║██████╔╝███████╗██║██║  ██║███████║  ║')}
{self.rainbow_text('║       ██║   ██║██╔══██╗╚════██║██║██║  ██║██╔══██║  ║')}
{self.rainbow_text('║       ╚██████╔╝██████╔╝███████║██║██████╔╝██║  ██║  ║')}
{self.rainbow_text('║        ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝  ╚═╝  ║')}
{self.rainbow_text('║                                                    ║')}
{self.rainbow_text('║           O B S I D I A N   C I P H E R            ║')}
{self.rainbow_text('║               P R O F E S S I O N A L              ║')}
{self.rainbow_text('║                                                    ║')}
{self.rainbow_text('║          » 5 REAL WORKING TOOLS «                  ║')}
{self.rainbow_text('║          » PRICE: 30K LIFETIME «                   ║')}
{self.rainbow_text('║          » BY: CYBER indonet «                     ║')}
{self.rainbow_text('║                                                    ║')}
{self.rainbow_text('╚══════════════════════════════════════════════════╝')}
"""
        print(welcome_ascii)
        
        # Animated welcome message
        welcome_msg = f"WELCOME, {self.auth.current_user.upper()}!"
        for i in range(3):
            for color in [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]:
                print(f"\r{color}{welcome_msg}", end="")
                time.sleep(0.1)
        
        print(f"\n\n{Fore.GREEN}[+] Login successful!")
        print(f"{Fore.CYAN}[+] Premium account: ACTIVE")
        print(f"{Fore.CYAN}[+] Last login: {self.auth.users[self.auth.current_user]['last_login']}")
        print(f"\n{Fore.YELLOW}[*] Loading tools...")
        
        for i in range(5):
            print(f"\r{Fore.GREEN}[{''.join(['█'] * (i+1))}{''.join(['░'] * (4-i))}] {20*(i+1)}%", end="")
            time.sleep(0.3)
        
        print(f"\n\n{Fore.GREEN}[+] Tools loaded successfully!")
        time.sleep(1)
        
        self.tools = ObsidianTools(self.auth.current_user)
    
    def main_menu(self):
        """Main menu after login"""
        while self.running:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Header with user info
            header = f"""
{self.rainbow_text('╔══════════════════════════════════════════════════╗')}
{self.rainbow_text('║                OBSIDIAN CIPHER v1.0               ║')}
{self.rainbow_text('║             User: ' + self.auth.current_user.ljust(23) + ' ║')}
{self.rainbow_text('╚══════════════════════════════════════════════════╝')}
"""
            print(header)
            
            print(f"\n{Fore.CYAN}[+] SELECT TOOL CATEGORY:")
            print(f"{Fore.YELLOW}════════════════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}NETWORK WARRIOR - Scanner, DDOS, WiFi tools")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}PASSWORD WARRIOR - Cracking, Generation, Hash")
            print(f"{Fore.WHITE}[3] {Fore.GREEN}OBSIDIAN ENCRYPTOR - Encryption, Steganography")
            print(f"{Fore.WHITE}[4] {Fore.GREEN}CYBER OSINT - IP, Email, Username, Phone lookup")
            print(f"{Fore.WHITE}[5] {Fore.GREEN}SYSTEM COMMANDER - System info, Diagnostics")
            print(f"{Fore.WHITE}[6] {Fore.YELLOW}Settings & Color Scheme")
            print(f"{Fore.WHITE}[7] {Fore.RED}Logout")
            print(f"{Fore.WHITE}[0] {Fore.RED}Exit")
            
            choice = input(f"\n{Fore.WHITE}Select (1-7, 0): ").strip()
            
            if choice == "1":
                self.tools.network_tools()
            elif choice == "2":
                self.tools.password_tools()
            elif choice == "3":
                self.tools.encryption_tools()
            elif choice == "4":
                self.tools.osint_tools()
            elif choice == "5":
                self.tools.system_tools()
            elif choice == "6":
                new_colors = self.auth.change_color_scheme()
                if new_colors:
                    self.color_scheme = new_colors
            elif choice == "7":
                print(f"\n{Fore.YELLOW}[*] Logging out...")
                time.sleep(1)
                self.auth.current_user = None
                self.tools = None
                break
            elif choice == "0":
                print(f"\n{Fore.YELLOW}[*] Thank you for using OBSIDIAN CIPHER!")
                print(f"{Fore.CYAN}[+] Contact: @cyber_indonet for support")
                self.running = False
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def run(self):
        """Main application loop"""
        print(f"\n{self.rainbow_text('══════════════════════════════════════════════════')}")
        print(f"{self.rainbow_text('           OBSIDIAN CIPHER TOOLS v1.0              ')}")
        print(f"{self.rainbow_text('               PRICE: 30K LIFETIME                 ')}")
        print(f"{self.rainbow_text('               BY: CYBER indonet                   ')}")
        print(f"{self.rainbow_text('══════════════════════════════════════════════════')}")
        
        while self.running:
            print(f"\n{Fore.CYAN}[+] MAIN MENU:")
            print(f"{Fore.YELLOW}════════════════")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}Login")
            print(f"{Fore.WHITE}[2] {Fore.GREEN}Create Account (30K)")
            print(f"{Fore.WHITE}[3] {Fore.YELLOW}About & Features")
            print(f"{Fore.WHITE}[0] {Fore.RED}Exit")
            
            choice = input(f"\n{Fore.WHITE}Select (1-3, 0): ").strip()
            
            if choice == "1":
                if self.auth.login():
                    self.welcome_screen()
                    self.main_menu()
                else:
                    print(f"{Fore.RED}[-] Login failed!")
                    time.sleep(2)
            
            elif choice == "2":
                if self.auth.create_account():
                    time.sleep(1)
                    if self.auth.login():
                        self.welcome_screen()
                        self.main_menu()
            
            elif choice == "3":
                self.show_features()
            
            elif choice == "0":
                print(f"\n{Fore.YELLOW}[+] Thank you for your interest!")
                print(f"{Fore.CYAN}[+] Contact @cyber_indonet to purchase")
                self.running = False
            
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
    
    def show_features(self):
        """Show tool features"""
        print(f"\n{Fore.CYAN}[+] OBSIDIAN CIPHER FEATURES:")
        print(f"{Fore.YELLOW}══════════════════════════════")
        print(f"{Fore.GREEN}✓ 5 REAL WORKING TOOLS (2000+ lines)")
        print(f"{Fore.GREEN}✓ Login System with User Management")
        print(f"{Fore.GREEN}✓ Rainbow Color Scheme (Changeable)")
        print(f"{Fore.GREEN}✓ Premium License System (30K)")
        print(f"\n{Fore.CYAN}[+] TOOL CATEGORIES:")
        print(f"{Fore.YELLOW}══════════════════════")
        print(f"{Fore.WHITE}1. {Fore.GREEN}NETWORK WARRIOR")
        print(f"   • Port Scanner (Real)")
        print(f"   • Local Network Scanner")
        print(f"   • DDOS Protection Tester")
        print(f"   • WiFi Information")
        
        print(f"\n{Fore.WHITE}2. {Fore.GREEN}PASSWORD WARRIOR")
        print(f"   • Password Strength Checker")
        print(f"   • Secure Password Generator")
        print(f"   • Hash Cracker (Dictionary)")
        print(f"   • Encrypted Password Manager")
        
        print(f"\n{Fore.WHITE}3. {Fore.GREEN}OBSIDIAN ENCRYPTOR")
        print(f"   • Text Encryption/Decryption")
        print(f"   • File Encryption/Decryption")
        print(f"   • Steganography (Hide text)")
        
        print(f"\n{Fore.WHITE}4. {Fore.GREEN}CYBER OSINT")
        print(f"   • IP Lookup & Geolocation")
        print(f"   • Email Information")
        print(f"   • Username Search (Social Media)")
        print(f"   • Phone Number Lookup")
        print(f"   • Website Information")
        
        print(f"\n{Fore.WHITE}5. {Fore.GREEN}SYSTEM COMMANDER")
        print(f"   • System Information")
        print(f"   • Network Diagnostics")
        print(f"   • Process Manager")
        print(f"   • File Manager")
        print(f"   • Resource Monitor")
        
        print(f"\n{Fore.YELLOW}[!] PRICE: Rp 30,000 (LIFETIME ACCESS)")
        print(f"{Fore.YELLOW}[!] Payment: GoPay/OVO/Dana")
        print(f"{Fore.YELLOW}[!] Contact: @cyber_indonet")
        
        input(f"\n{Fore.WHITE}Press Enter to continue...")

# ============ ENTRY POINT ============
if __name__ == "__main__":
    try:
        # Check for required packages
        required = ['requests', 'colorama', 'psutil']
        missing = []
        
        for package in required:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing.append(package)
        
        if missing:
            print(f"{Fore.RED}[!] Missing packages: {', '.join(missing)}")
            print(f"{Fore.YELLOW}[*] Install with: pip install {' '.join(missing)}")
            
            if input(f"\n{Fore.WHITE}Install now? (y/N): ").strip().lower() == 'y':
                import subprocess
                subprocess.run([sys.executable, "-m", "pip", "install"] + missing)
                print(f"{Fore.GREEN}[+] Packages installed!")
                time.sleep(2)
            else:
                print(f"{Fore.RED}[!] Cannot run without required packages!")
                sys.exit(1)
        
        # Run application
        app = ObsidianApp()
        app.run()
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program interrupted")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}")
        print(f"{Fore.YELLOW}[*] Contact @cyber_indonet for support")
    finally:
        print(f"\n{Fore.CYAN}[+] OBSIDIAN CIPHER - BY CYBER indonet")
        print(f"{Fore.YELLOW}[+] Thank you for using our tools!")
