@echo off
schtasks /create /tn "UF Deployer" /tr "\"%~dp0start.bat\" --no-browser" /sc onlogon /f
if errorlevel 1 (echo Failed - run this file as Administrator) else (echo Done. UF Deployer will start at every logon: http://127.0.0.1:8000)
pause
