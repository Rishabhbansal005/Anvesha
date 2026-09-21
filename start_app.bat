@echo off
cd /d "%~dp0"
echo =====================================================================
echo Launching ANVESH Full Cyber Forensic Web Platform...
echo =====================================================================
echo.

REM 1. Start Backend Server in a new window
echo [1/2] Starting FastAPI Core Backend (Port 8000)...
start "ANVESH Backend Core" cmd /k "cd /d "%~dp0backend" && ".\venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

REM 2. Wait 2 seconds for backend to initialize
timeout /t 2 /nobreak >nul

REM 3. Start Web Workstation in a new window
echo [2/2] Starting React Web Workstation (Port 5173)...
start "ANVESH Web Workstation" cmd /k "set "PATH=C:\Program Files\nodejs\;%PATH%" && cd /d "%~dp0web" && npm run dev"

REM 4. Wait 2 seconds and open browser
timeout /t 2 /nobreak >nul
start http://localhost:5173

echo.
echo =====================================================================
echo ANVESH Platform is online!
echo  * Web Workstation: http://localhost:5173
echo  * Backend API:     http://localhost:8000/docs
echo =====================================================================
pause
