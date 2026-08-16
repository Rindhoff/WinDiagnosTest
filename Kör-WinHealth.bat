@echo off
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process '%~dp0WinHealth.exe' -Verb RunAs"
