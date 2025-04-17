@echo off
echo [*] Running as admin...
:: Requires Admin Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run this script as administrator.
    pause
    exit /b
)

:: Disable Defender via PowerShell
echo [*] Disabling Windows Defender...

powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell -Command "Set-MpPreference -DisableIOAVProtection $true"
powershell -Command "Set-MpPreference -DisableScriptScanning $true"
powershell -Command "Set-MpPreference -DisableIntrusionPreventionSystem $true"
powershell -Command "Set-MpPreference -MAPSReporting 0"
powershell -Command "Set-MpPreference -SubmitSamplesConsent 2"

:: Optional: Disable scheduled scans
powershell -Command "Set-MpPreference -DisableScheduledScans $true"

:: Block Defender via Registry (may fail with Tamper Protection on)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

echo [*] Attempted to disable Defender. Check Windows Security for status.
pause
