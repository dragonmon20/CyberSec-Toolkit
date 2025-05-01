# CyberSec-Toolkit 🛡️

![Security](https://img.shields.io/badge/Security-Testing-red)
![License](https://img.shields.io/badge/License-MIT-blue)
![Purpose](https://img.shields.io/badge/Purpose-Educational-green)

⚠️ **DISCLAIMER**: This repository contains cybersecurity tools intended **STRICTLY** for educational purposes, security research, and authorized penetration testing. Usage of these tools against any systems without explicit permission is illegal and unethical.

## 📋 Repository Overview

A comprehensive collection of cybersecurity tools organized by category, designed for security professionals, penetration testers, and cybersecurity students to understand various attack vectors and defense mechanisms.

## 📂 Repository Structure

```
CyberSec-Toolkit/
├── LICENSE
├── profile.md
├── README.md
├── SECURITY.md
├── structure.txt
├── .vscode/
│   └── settings.json
│
├── Expolitation tools/
│   └── SQL/
│       ├── Injection.py             # Basic SQL injection framework
│       └── injectionV2.py           # Advanced SQL injection with extended capabilities
│
├── malware analyzers/
│   ├── BasicSandBox.py              # Simple malware sandbox environment
│   └── readme.md                    # Analyzer documentation
│
├── Malware tools/
│   ├── back-doot/
│   │   ├── backDoor.cpp             # Core backdoor implementation
│   │   ├── backDoor.h               # Header definitions
│   │   └── main.cpp                 # Main program entry point
│   │
│   └── Ransomwares/
│       └── PowerShell/
│           ├── decrypt.ps1          # Decryption demonstration script
│           └── encrypt.ps1          # Encryption demonstration script
│
├── network/
│   └── network-tools/
│       ├── anonymous-tools/
│       │   ├── anonymous.py         # Network anonymization utilities
│       │   └── readme.md            # Usage documentation
│       │
│       ├── DNS/
│       │   ├── readme.md            # DNS tool documentation
│       │   └── DOS-attack/
│       │       └── Dos-Attack.py    # DNS denial of service simulation
│       │
│       ├── scanner/
│       │   ├── C++/
│       │   │   ├── readme.md        # C++ scanner documentation
│       │   │   └── scanner.cpp      # Network scanner in C++
│       │   │
│       │   └── python/
│       │       ├── readme.md        # Python scanner documentation
│       │       └── scanner.py       # Network scanner in Python
│       │
│       └── wifi/
│           └── Deauthenticator.py   # Wi-Fi deauthentication testing tool
│
├── Utility Tools/
│   ├── file cracker/
│   │   ├── fileCracker.py           # Password-protected file analysis
│   │   └── readme.md                # Usage guidelines
│   │
│   └── hashReader/
│       └── hashReader.py            # Hash identification and analysis
│
└── Windows Tools/
    ├── backup/
    │   └── extract info/
    │       └── extract_info.bat     # System information extraction tool
    │
    ├── Disable-Defender/
    │   ├── Disable-Defender.bat     # Windows Defender testing utility
    │   └── readme.md                # Documentation and warnings
    │
    ├── make windows ready/
    │   └── readme.md                # Windows preparation guidelines
    │
    ├── restore point/
    │   └── create_restore_point.bat # System restore point creation utility
    │
    └── Windows Recall Feature Management/
        └── readme.md                # Documentation for Windows recall features
```

## 🧰 Tool Categories

### 💉 Exploitation Tools
Tools designed to demonstrate common exploitation techniques:
- **SQL Injection**: Python-based tools for testing SQL database security

### 🔍 Malware Analyzers
Tools for safely analyzing malicious software:
- **Basic Sandbox**: Python-based environment for controlled malware execution

### 🦠 Malware Analysis Tools
Educational implementations of malware techniques for security understanding:
- **Backdoor Demonstration**: C++ implementation for educational analysis
- **Ransomware Simulation**: PowerShell scripts demonstrating encryption/decryption mechanics

### 🌐 Network Security Tools
Network analysis and testing utilities:
- **Anonymization Tools**: Methods for secure and private network communication
- **DNS Security**: Tools for DNS server analysis and security testing
- **Network Scanning**: Multi-language implementations of network reconnaissance tools
- **Wireless Security**: Wi-Fi security assessment tools

### 🪟 Windows Tools
Windows-specific security utilities:
- **Backup Tools**: System information extraction and backup
- **Defender Management**: Tools for testing security software configurations
- **System Preparation**: Windows security preparation utilities
- **System Restore**: Restore point creation and management
- **Windows Feature Management**: Control and configuration of Windows features

### 🔧 Utility Tools
Supporting tools for security analysis:
- **File Analysis**: Tools for analyzing password-protected files
- **Hash Analysis**: Utilities for working with cryptographic hashes

## 🚀 Intended Usage

This toolkit is designed for:
- Cybersecurity education and training
- Authorized penetration testing
- Security research and development
- Understanding attack vectors for better defense implementation

## 🏁 Getting Started

Each tool directory contains its own readme with specific:
- Installation requirements
- Usage instructions
- Examples
- Safety considerations

## 🔰 Ethical Guidelines

1. **Always obtain explicit permission** before testing any system you don't own
2. **Document all testing activities** thoroughly
3. **Report vulnerabilities responsibly** to the appropriate parties
4. **Never use these tools for malicious purposes**
5. **Follow responsible disclosure practices**

## ⚖️ Legal Notice

Unauthorized use of these tools against systems without explicit permission violates various computer crime laws including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States and similar laws worldwide. Users are solely responsible for ensuring their activities comply with all applicable laws and regulations.

## 👥 Contributing

Please refer to SECURITY.md for contribution guidelines and our security policy. We welcome improvements that enhance the educational value of this repository while maintaining ethical standards.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

© 2025 [Amr Khaled Ahmed](https://github.com/Amr-Khaled-Ahmed)