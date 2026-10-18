@echo off
cd /d "%~dp0"
start "UF Deployer" /min python app.py %*
