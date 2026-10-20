@echo off
cd /d "%~dp0"
echo [1/2] Installing requirements...
pip install -r requirements.txt pyinstaller || goto :err
echo [2/2] Building UFDeployer.exe ...
pyinstaller --noconfirm --onefile --name UFDeployer --collect-all winrm --collect-submodules paramiko --add-data "index.html;." app.py || goto :err
echo Done: dist\UFDeployer.exe  (its data\ folder is created next to the exe)
pause
exit /b 0
:err
echo Build failed.
pause
exit /b 1
