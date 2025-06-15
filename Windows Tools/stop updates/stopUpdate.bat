@echo off
title Disable Windows Update Permanently
echo.
echo *** Disabling Windows Update Services ***

:: Stop Windows Update service
sc stop wuauserv
sc config wuauserv start= disabled

:: Stop Update Orchestrator service (Windows 10+)
sc stop UsoSvc
sc config UsoSvc start= disabled

:: Stop Delivery Optimization
sc stop DoSvc
sc config DoSvc start= disabled

:: Disable Windows Update Medic Service (only via registry)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d 4 /f

:: Disable Update Orchestrator Scheduled Tasks
echo *** Disabling Scheduled Tasks ***
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\ScheduleScan" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sih" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sihboot" /Disable

echo.
echo *** Blocking Windows Update Domains (optional) ***
:: Uncomment if you want to block at firewall level too
:: netsh advfirewall firewall add rule name="Block Windows Update" dir=out action=block remoteip=13.107.4.50,13.107.5.88,23.223.103.50 enable=yes

echo.
echo Windows Update should now be permanently disabled.
pause
