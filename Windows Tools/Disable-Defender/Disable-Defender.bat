@echo off
title 🔒 Disabling Windows Defender Permanently
color 0C

:: Ensure Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run this script as Administrator.
    pause
    exit /b
)

echo [*] Stopping Windows Defender services...
sc stop WinDefend >nul 2>&1
sc config WinDefend start= disabled >nul 2>&1

echo [*] Disabling Defender via Registry...

:: Disable Real-Time Protection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

:: Disable AntiSpyware
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

:: Disable Tamper Protection (requires manual GUI or script via Task Scheduler workaround)

:: Disable Windows Defender Security Center
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray /t REG_DWORD /d 1 /f

echo [*] Disabling Defender Scheduled Tasks...
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul 2>&1

echo [✓] Defender should now be disabled permanently.
echo [!] A system restart is recommended.

pause
