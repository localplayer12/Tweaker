
:-------------------------------------        
REM  --> Check for permissions  
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"  
REM --> If error flag set, we do not have admin.  
if '%errorlevel%' NEQ '0' (    echo Requesting administrative privileges...    ) else ( goto gotAdmin )  
:UACPrompt  
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"  
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"  
    "%temp%\getadmin.vbs"  
    exit /B
:gotAdmin  

@echo off
setlocal enabledelayedexpansion

:menu
cls

:::  ____  __.       /\      ___________                      __            
::: |    |/  |___.__ \/_____ \__    ___/_  _  __ ____ _____  |  | __  ______
::: |       /<   |  |/  ___/   |    |  \ \/ \/ // __ \\__  \ |  |/ / /  ___/
::: |    |  \ \___  |\___ \    |    |   \     /\  ___/ / __ \|    <  \___ \ 
::: |____|__ \/ ____/____  >   |____|    \/\_/  \___  >____  /__|_ \/____  >
:::         \/\/         \/                         \/     \/     \/     \/ 

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

echo Please select an option:
echo 1. System Care
echo 2. Priority Tweaks
echo 3. Install Features
echo 4. Exit

set /p "option=Enter your choice: "
set "count=3"
if "%option%"=="1" (
    call :call_system
) else if "%option%"=="2" (
    call :priority_tweaks
) else if "%option%"=="3" (
    call :Install_Features
) else if "%option%"=="4" (
    exit /b
) else (
    echo Invalid option. Please enter a valid option.
    pause
    goto :menu
)

REM  --> Second Menu
:menu2
cls
echo Please select an option:
echo 1. System Care
echo 2. Clean PC
echo 3. Tweak PC
echo 4. Exit

set /p "option=Enter your choice: "
set "count=4"
if "%option%"=="1" (
    call :system_care
) else if "%option%"=="2" (
    call :clean
) else if "%option%"=="3" (
    call :Tweak_PC
) else if "%option%"=="4" (
    goto :menu
) else (
    echo Invalid option. Please enter a valid option.
    pause
    goto :menu2
)

:call_system
cls
call :menu2

:system_care
cls
echo Performing System Care...

echo Running Disk Cleanup...
cleanmgr /sagerun:1

echo Resetting Winsock...
netsh winsock reset

echo Resetting TCP/IP stack...
netsh int ip reset resetlog.txt

for /f "tokens=3" %%A in ('fsutil volume diskfree c:') do set "oldsize=%%A"
echo Before compacting: %oldsize% bytes
echo Compacting OS...
compact /compactos:always >nul 2>&1
for /f "tokens=3" %%B in ('fsutil volume diskfree c:') do set "newsize=%%B"
echo After compacting: %newsize% bytes

set /a "difference=newsize-oldsize"
echo The disk size has changed by %difference% bytes.

echo Repairing System Files...
sfc /scannow

echo Disabling SysMain service...
sc config sysmain start=disabled >nul 2>&1
sc stop sysmain >nul 2>&1

echo Editing Wait to Kill Threshold...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "2000" /f >nul 2>&1

echo Turning off Background Apps...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f >nul 2>&1

echo Turning off Hibernation...
powercfg -h off

echo System Care tasks completed.

pause
goto :menu

:clean
cls
echo Emptying Recycle Bin...
rd /s /q C:\$Recycle.Bin >nul 2>&1

echo Deleting Temp Files...
del /F /Q %TEMP%\*.* >nul 2>&1

echo Cleaning up prefetch data...
del /q /s /f %windir%\Prefetch\*.* >nul 2>&1

echo Deleting Install Files...
rmdir /q /s "%systemroot%\SoftwareDistribution\Download" >nul 2>&1

echo Cleaning Installer Files...
msizap G! >nul 2>&1

echo Cleaning Quick Access...
del /F /Q %APPDATA%\Microsoft\Windows\Recent\*
del /F /Q %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*
del /F /Q %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*

echo Clearing Event Logs...
wevtutil cl Application >nul 2>&1
wevtutil cl Security >nul 2>&1
wevtutil cl System >nul 2>&1

cls
echo Your PC is now cleaned!
pause
goto :menu

:Tweak_PC

set key="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
reg add %key% /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add %key% /v "Priority" /t REG_DWORD /d 6 /f
reg add %key% /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add %key% /v "SFIO Priority" /t REG_SZ /d "High" /f
echo Priority Changed...

powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 2; Start-Process -FilePath 'rundll32.exe' -ArgumentList 'shell32.dll,Control_RunDLL sysdm.cpl,,3' -Verb RunAs"
echo Visuals Changed...

REG ADD "HKEY_CURRENT_USER\Control Panel\Cursors" /v MenuShowDelay /t REG_SZ /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 26 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{InterfaceID}" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{InterfaceID}" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
echo Registry Tweaked...

sc stop "SysMain"
sc config "SysMain" start=disabled
sc stop "wuauserv"
sc config "wuauserv" start=disabled
echo Services Tweaked...

echo PC Tweaked...
pause
goto :menu

REM  --> Third Menu
:menu3
cls
echo Please select an option:
echo 1. Game Priority
echo 2. Priorities Adjustments
echo 3. Exit

set /p "option=Enter your choice: "
set "count=3"
if "%option%"=="1" (
    call :game_tweaks
) else if "%option%"=="2" (
    call :priority_changes
) else if "%option%"=="3" (
    goto :menu
) else (
    echo Invalid option. Please enter a valid option.
    pause
    goto :menu3
)

:priority_tweaks
cls
call :menu3

:game_tweaks
cls
set /p "gameExecutable=Enter the name of the game executable (e.g., YourGame.exe): "

set "extension=!gameExecutable:~-4!"
if /i not "!extension!"==".exe" (
    echo Error: Please provide the name of the game executable ending with ".exe". Example: YourGame.exe
    echo Closing in !count! seconds...
    pause
    goto :menu
)

if "!gameExecutable!"=="" (
    echo Error: No game executable name provided. Please try again.
    echo Closing in !count! seconds...
    
    pause
    goto :menu
)

echo Setting priority of !gameExecutable! to High...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\!gameExecutable!\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 0x00000003 /f > nul

cls
echo Priority set to High for !gameExecutable!.
echo Priority Tweaked...
pause
goto :menu

:priority_changes
set key="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

reg add %key% /v "GPU Priority" /t REG_DWORD /d 8 /f

reg add %key% /v "Priority" /t REG_DWORD /d 6 /f

reg add %key% /v "Scheduling Category" /t REG_SZ /d "High" /f

reg add %key% /v "SFIO Priority" /t REG_SZ /d "High" /f

cls
echo Priority Tweaked...
pause
goto :menu

:Install_Features

@echo off
setlocal

set "VC_REDIST_X86_URL=https://aka.ms/vs/16/release/vc_redist.x86.exe"
set "VC_REDIST_X64_URL=https://aka.ms/vs/16/release/vc_redist.x64.exe"

set "VC_REDIST_X86_FILE=vc_redist.x86.exe"
set "VC_REDIST_X64_FILE=vc_redist.x64.exe"

set "TEMP_DIR=%TEMP%\VC_Redistributable"

mkdir "%TEMP_DIR%"

echo Downloading Visual C++ Redistributable x86...
powershell -command "Invoke-WebRequest -Uri %VC_REDIST_X86_URL% -OutFile '%TEMP_DIR%\%VC_REDIST_X86_FILE%'"

echo Downloading Visual C++ Redistributable x64...
powershell -command "Invoke-WebRequest -Uri %VC_REDIST_X64_URL% -OutFile '%TEMP_DIR%\%VC_REDIST_X64_FILE%'"

echo Installing Visual C++ Redistributable x86...
start /wait "%TEMP_DIR%\%VC_REDIST_X86_FILE%" /quiet /norestart

echo Installing Visual C++ Redistributable x64...
start /wait "%TEMP_DIR%\%VC_REDIST_X64_FILE%" /quiet /norestart

echo Cleaning up...
del /q "%TEMP_DIR%\%VC_REDIST_X86_FILE%"
del /q "%TEMP_DIR%\%VC_REDIST_X64_FILE%"
rmdir /s /q "%TEMP_DIR%"

echo Installed All...
pause
endlocal
goto :menu
