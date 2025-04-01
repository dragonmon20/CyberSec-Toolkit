# Network Scanner - `scanner.py`

⚠ **Warning**: This tool is intended for educational and ethical use only. Unauthorized use is strictly prohibited.

## Overview

`scanner.py` is a Python-based network scanning tool designed to identify open ports, detect operating systems, and test firewall bypass techniques. It provides multiple scanning modes to help users understand network vulnerabilities and improve security.

### Features

- **Advanced Scan**: Scans all ports (TCP and UDP) on a target IP and attempts to detect the operating system.
- **Firewall Bypass Scan**: Simulates decoy IPs to evade firewalls and detect open ports.
- **Stealth Scan**: Performs a stealthy SYN scan to identify open ports without completing the TCP handshake.
- **Banner Grabbing**: Attempts to retrieve service banners from open ports.
- **OS Detection**: Uses TTL values to infer the target's operating system.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Amr-Khaled-Ahmed/Hack-Tools.git
   cd Hack-Tools/network/network-tools
