@echo off
echo Bygger WinHealth.exe...
set "PATH=%PATH%;%USERPROFILE%\go\bin;C:\Program Files\Go\bin;C:\Program Files\nodejs"
wails build -o WinHealth.exe
copy /Y "build\bin\WinHealth.exe" "WinHealth.exe"
echo Klart! WinHealth.exe ar nu uppdaterad.
pause
