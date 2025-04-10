# CyberSec-Toolkit

A collection of cybersecurity tools for network analysis and security testing.

## Port Scanner

A multi-threaded TCP port scanner written in C++ for efficient network reconnaissance. This tool allows you to quickly identify open ports on a target system using concurrent scanning techniques.

### Features

- **Multi-threaded scanning**: Distribute scanning workload across multiple threads for faster results
- **Customizable port range**: Scan specific port ranges as needed
- **Adjustable timeout**: Configure connection timeout to balance between speed and accuracy
- **Colored output**: Easy-to-read terminal output with color-coded results
- **Open port tracking**: Keeps count of discovered open ports

### Requirements

- Windows operating system
- C++ compiler with C++11 support
- Winsock2 library (ws2_32.lib)

### Building the Port Scanner

```bash
# Using g++
g++ -o port_scanner port_scanner.cpp -lws2_32 -std=c++11

# Using Visual Studio
# Add ws2_32.lib to your project dependencies
```

### Usage

1. Run the compiled executable
2. Enter the target IP address
3. Specify the start and end ports to scan
4. Set the number of threads to use
5. Define the timeout value in milliseconds

```
Enter IP to scan: 192.168.1.1
Enter start port: 1
Enter end port: 1024
Enter number of threads: 10
Enter timeout in milliseconds: 100

Starting scan on 192.168.1.1 from port 1 to 1024...
[+] Port 21 is OPEN
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[-] Port 81 is CLOSED
...

Scan complete. Open ports found: 3
```

### How It Works

The scanner uses TCP connect() method to determine if a port is open:
1. Creates a socket for each connection attempt
2. Sets a timeout to avoid hanging on filtered ports
3. Attempts to establish a connection to each port
4. Reports results based on connection success or failure

### Security and Ethical Usage

This tool is intended for:
- Network administrators testing their own systems
- Security professionals conducting authorized security assessments
- Educational purposes to understand network scanning techniques

**IMPORTANT**: Only use this tool on systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal in many jurisdictions.

