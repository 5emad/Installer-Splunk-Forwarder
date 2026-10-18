@echo off
cd /d "%~dp0"
echo [1/3] Installing requirements...
pip install -r requirements.txt pyinstaller || goto :err
set "IDX=static\index.html"
set "DEST=static"
if not exist "%IDX%" (
  set "IDX=index.html"
  set "DEST=."
)
echo [2/3] Building UFDeployer.exe ...
pyinstaller --noconfirm --onefile --name UFDeployer --collect-all uvicorn --collect-all winrm --collect-all netmiko --collect-submodules paramiko --add-data "%IDX%;%DEST%" app.py || goto :err
echo [3/3] Done: dist\UFDeployer.exe
echo For a real installer (Setup.exe): install Inno Setup, then open setup.iss and press Compile.
pause
exit /b 0
:err
echo Build failed.
pause
exit /b 1
