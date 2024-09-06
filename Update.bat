@echo off
setlocal

set URL=https://raw.githubusercontent.com/localplayer12/Tweaker/main/Xero.bat

set OUTPUT=Xero.bat

curl -L -o %OUTPUT% %URL%

if exist %OUTPUT% (
    echo Download completed successfully.
) else (
    echo Failed to download the file.
)

endlocal
pause
