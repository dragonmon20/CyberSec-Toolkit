# 🛡️ Malware Analysis Environment Preparer

![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Security](https://img.shields.io/badge/Security-Expert-yellow?style=for-the-badge)

A PowerShell script to automatically configure a Windows VM for safe malware analysis by disabling security features and enabling comprehensive logging.

## ⚠️ Important Warning
> **This script disables critical security features!**  
> Only run this in isolated virtual machines dedicated to malware analysis.  
> Never use on production systems or internet-connected machines.

## ✨ Features

### 🔒 Security Feature Disabling
- 🛡️ Windows Defender real-time protection
- 🚫 SmartScreen filter
- 🛑 User Account Control (UAC)

### 📝 Enhanced Logging
- 📜 PowerShell script block logging
- 🎤 PowerShell transcription
- 📝 Command line process auditing
- 💥 Full system crash dumps

### 🛠️ Additional Configuration
- 🔍 Show hidden files and extensions
- 📁 Configure Sysmon (if installed)
- 📊 Set up centralized logging directory

## 🚀 Usage

1. **Prepare your VM** - Start with a clean Windows VM snapshot
2. **Run as Administrator** - Launch PowerShell as admin
3. **Execute the script** - Let it configure your environment
4. **Analyze malware safely** - All logging will be active

## 📂 Log Outputs
All logs are saved to:
- `C:\Logs\PS\` - PowerShell transcripts
- System event logs - Process creation events
- Memory dumps - For crash analysis

## 🔧 Recommended VM Setup
- ⚡ 4GB+ RAM
- 💾 60GB+ disk space
- 🖥️ Windows 10/11
- 🔄 Take snapshot before running!

## 📌 Best Practices
- 🕵️ Always analyze malware in isolated VMs
- 📸 Take snapshots before execution
- 🌐 Disable network when not needed
- 🔄 Revert to clean snapshot after analysis

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits
Developed by [Your Name] for malware analysts and security researchers.

---

> **Remember**: With great power comes great responsibility. Use this tool ethically and only for legitimate security research purposes.
