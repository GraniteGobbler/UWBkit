@echo off
setlocal
set SCRIPT_DIR=%~dp0
set VENV_DIR=%SCRIPT_DIR%.venv

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    set PY_LAUNCHER=py -3
) else (
    set PY_LAUNCHER=python
)

echo Creating virtual environment in %VENV_DIR%
%PY_LAUNCHER% -m venv "%VENV_DIR%"
if errorlevel 1 goto :fail

echo Upgrading pip
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :fail

echo Installing requirements
"%VENV_DIR%\Scripts\python.exe" -m pip install -r "%SCRIPT_DIR%requirements.txt"
if errorlevel 1 goto :fail

echo.
echo Done. Use run_serial_to_zep_udp.bat to start the bridge.
goto :eof

:fail
echo.
echo Setup failed.
exit /b 1
