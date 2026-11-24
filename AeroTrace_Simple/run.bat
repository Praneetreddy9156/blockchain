@echo off
rem AeroTrace Simple - double-click to start, then use the browser window that opens.
rem Close this window to stop the server. Academic demonstration - synthetic data only.
cd /d "%~dp0"
set "PY=..\backend\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" (
  echo First run: creating a Python environment and installing the packages...
  python -m venv .venv || goto nopython
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto failed
)
echo Starting AeroTrace Simple on http://localhost:8100 ...
start "" cmd /c "ping -n 3 127.0.0.1 >nul & start http://localhost:8100"
"%PY%" -m uvicorn app:app --host 127.0.0.1 --port 8100
pause
exit /b 0

:nopython
echo Python was not found. Install Python 3.10 or newer from python.org and run this file again.
pause
exit /b 1

:failed
echo Installing the packages failed. See the messages above.
pause
exit /b 1
