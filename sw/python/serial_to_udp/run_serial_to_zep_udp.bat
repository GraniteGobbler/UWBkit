@echo off
setlocal

set PORT=COM6
set BAUD=115200
set HOST=127.0.0.1
set UDP_PORT=17754
set SCRIPT_DIR=%~dp0

set PYTHON_EXE=
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" set PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe
if not defined PYTHON_EXE if exist "%SCRIPT_DIR%venv\Scripts\python.exe" set PYTHON_EXE=%SCRIPT_DIR%venv\Scripts\python.exe
if not defined PYTHON_EXE set PYTHON_EXE=python

echo Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" "%SCRIPT_DIR%serial_to_zep_udp.py" --port %PORT% --baud %BAUD% --host %HOST% --udp-port %UDP_PORT% --verbose --log-wait
pause