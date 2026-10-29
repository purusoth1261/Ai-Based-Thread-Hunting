@echo off
setlocal
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    py -m venv venv
    if errorlevel 1 goto failed
)

venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto failed

venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed

venv\Scripts\python.exe scripts\download_assets.py
if errorlevel 1 goto failed

echo.
echo Setup completed.
echo Start the application with:
echo venv\Scripts\python.exe app.py
pause
exit /b 0

:failed
echo.
echo Setup failed. Read the error above.
pause
exit /b 1