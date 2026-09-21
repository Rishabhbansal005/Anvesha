@echo off
set "PATH=C:\Program Files\nodejs\;%PATH%"
cd /d "%~dp0backend"
echo ===================================================
echo Starting ANVESH Backend Server...
echo ===================================================
".\venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
