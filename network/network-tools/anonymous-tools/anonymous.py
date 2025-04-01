#!/usr/bin/env python3
import socket
import argparse
from termcolor import colored

# Default ports for common services
SERVICE_PORTS = {
    'ftp': 21,
    'smtp': 25,
    'telnet': 23,
    'rsync': 873,
    'samba': 445
}

def check_anonymous_access(host, port, service):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))

            if service == 'ftp':
                s.recv(1024)
                s.send(b"USER anonymous\r\n")
                response = s.recv(1024).decode()
                if "331" in response:  # Password required
                    s.send(b"PASS anonymous\r\n")
                    response = s.recv(1024).decode()
                    if "230" in response:  # Login successful
                        return True, response

            elif service == 'smtp':
                response = s.recv(1024).decode()
                if "220" in response:
                    s.send(b"EHLO anonymous\r\n")
                    response = s.recv(1024).decode()
                    if "250" in response:
                        return True, response

            elif service == 'rsync':
                s.send(b"\n")
                response = s.recv(1024).decode()
                if "@RSYNCD" in response:
                    s.send(b"anonymous\n")
                    response = s.recv(1024).decode()
                    if "RSYNCD" in response and "OK" in response:
                        return True, response

            return False, response if 'response' in locals() else "No response"

    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description="Anonymous Access Vulnerability Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, help="Custom port number")
    parser.add_argument("-s", "--service", choices=SERVICE_PORTS.keys(),
                       help="Service type (default: auto-detect)")

    args = parser.parse_args()

    host = args.host
    services_to_check = []

    if args.service:
        services_to_check = [(args.service, args.port or SERVICE_PORTS[args.service])]
    else:
        print(colored("[*] Auto-detecting services...", "yellow"))
        services_to_check = [(service, SERVICE_PORTS[service]) for service in SERVICE_PORTS]

    for service, port in services_to_check:
        print(colored(f"\n[*] Checking {service.upper()} on {host}:{port}", "blue"))
        vulnerable, response = check_anonymous_access(host, port, service)

        if vulnerable:
            print(colored(f"[!] VULNERABLE: Anonymous access allowed on {service.upper()}", "red"))
            print(colored(f"    Response: {response.strip()}", "yellow"))
        else:
            print(colored(f"[+] Secure: No anonymous access on {service.upper()}", "green"))

if __name__ == "__main__":
    banner = """
    █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗██╗   ██╗ ██████╗ ██╗   ██╗███████╗
    ██╔══██╗████╗  ██║██╔═══██╗████╗  ██║██║   ██║██╔═══██╗██║   ██║██╔════╝
    ███████║██╔██╗ ██║██║   ██║██╔██╗ ██║██║   ██║██║   ██║██║   ██║███████╗
    ██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║██║   ██║██║   ██║██║   ██║╚════██║
    ██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝
    """
    print(colored(banner, "cyan"))
    print(colored("Anonymous Service Access Scanner\n", "yellow"))
    print(colored("WARNING: Only use on systems you have permission to scan!\n", "red"))

    main()
