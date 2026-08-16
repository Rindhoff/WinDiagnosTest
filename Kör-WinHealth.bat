@echo off
cd /d "%~dp0"
if exist "%~dp0build\bin\WinHealth.exe" (
    copy /y "%~dp0build\bin\WinHealth.exe" "%~dp0WinHealth.exe" >nul 2>&1
)
powershell -NoProfile -Command "Start-Process '%~dp0WinHealth.exe' -Verb RunAs"
