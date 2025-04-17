# Windows Defender Management Tool

## Overview
This script temporarily disables certain Windows Defender features for system maintenance or troubleshooting purposes. Please use with caution and only when necessary.

## Requirements
- Administrator privileges
- Windows operating system with Windows Defender

## Usage
1. Right-click on the script file (.bat)
2. Select "Run as administrator"
3. Follow any on-screen prompts

## Features
- Checks for administrative privileges
- Temporarily disables real-time monitoring
- Disables behavior monitoring
- Disables script scanning
- Modifies other Windows Defender preferences

## Important Notes
- This is intended for temporary use during system maintenance
- Windows Defender will typically re-enable itself after a system restart
- Not recommended for everyday use
- May be blocked by Windows Defender Tamper Protection if enabled

## Restoring Windows Defender
To restore Windows Defender protection:
1. Open Windows Security
2. Navigate to Virus & threat protection
3. Turn on Real-time protection

## Disclaimer
Use this script at your own risk. Disabling security features may leave your system vulnerable. Always re-enable Windows Defender when finished with your maintenance tasks.
