import socket
import threading
import random
import time
from scapy.all import *

# Colors for output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

# Common Service Ports
COMMON_PORTS = {80: "HTTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}

def get_banner(ip, port):
    """Attempts to grab the service banner from an open port."""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b'\r\n')
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner if banner else "Unknown Service"
    except:
        return "Unknown Service"

def detect_os(ip):
    """Performs a simple OS detection using TTL values."""
    try:
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            ttl = response.ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
        return "Unknown"
    except:
        return "Unknown"

def scan_port(ip, port):
    try:
        # TCP SCAN
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = get_banner(ip, port)
            real_service = banner if banner != "Unknown Service" else COMMON_PORTS.get(port, "Unknown")
            expected_service = COMMON_PORTS.get(port, "Unknown")
            status = f"{GREEN}[+] Port {port}/TCP is OPEN ({real_service}){RESET}"
            if real_service != expected_service:
                status += f" {RED}(Possible Protocol Mismatch! Expected {expected_service}){RESET}"
            print(status)
        sock.close()

        # UDP SCAN
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.sendto(b"\x00", (ip, port))  # Send dummy payload
        udp_sock.settimeout(1)
        try:
            data, _ = udp_sock.recvfrom(1024)
            print(f"{YELLOW}[+] Port {port}/UDP is OPEN (Response Received){RESET}")
        except socket.timeout:
            pass
        udp_sock.close()
    except Exception as e:
        pass

def advanced_scan(ip):
    print(f"{CYAN}Scanning {ip}...\n{RESET}")
    os_detected = detect_os(ip)
    print(f"{MAGENTA}Detected OS: {os_detected}{RESET}\n")
    threads = []
    for port in range(1, 65536):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()
        threads.append(thread)
        if port % 100 == 0:
            for t in threads:
                t.join()
            threads = []

def firewall_bypass_scan(ip):
    print(f"{MAGENTA}[+] Trying to bypass firewall...{RESET}")
    decoys = ["192.168.1.100", "8.8.8.8", "8.8.4.4", "192.168.1.200"]
    for port in range(1, 65536):
        ip_to_use = random.choice(decoys + [ip])
        packet = IP(src=ip_to_use, dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            banner = get_banner(ip, port)
            print(f"{GREEN}[+] Port {port} is OPEN on {ip} ({banner}) (Firewall evasion){RESET}")

def stealth_scan(ip):
    print(f"{BLUE}[+] Performing Stealth Scan...{RESET}")
    for port in range(1, 65536):
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            print(f"{GREEN}[+] Port {port} is OPEN (Stealth Mode){RESET}")
            send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)  # Send RST to avoid detection

def main():
    target_ip = input(f"{BLUE}Enter target IP: {RESET}")
    choice = input(f"{CYAN}Select scan type:\n1. Advanced Scan\n2. Firewall Bypass\n3. Stealth Scan\nChoice: {RESET}")
    if choice == "1":
        advanced_scan(target_ip)
    elif choice == "2":
        firewall_bypass_scan(target_ip)
    elif choice == "3":
        stealth_scan(target_ip)
    else:
        print(f"{RED}Invalid choice!{RESET}")

if __name__ == "__main__":
    main()
