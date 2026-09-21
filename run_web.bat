@echo off
set "PATH=C:\Program Files\nodejs\;%PATH%"
cd /d "%~dp0web"
echo ===================================================
echo Starting ANVESH Web Workstation...
echo ===================================================
call "C:\Program Files\nodejs\npm.cmd" run dev
pause
