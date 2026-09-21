# Start PROJECT_NAME FastAPI Backend
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "Starting PROJECT_NAME FastAPI Backend on Port 8000..." -ForegroundColor Green
Write-Host "Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "======================================================" -ForegroundColor Cyan

Set-Location -Path "$PSScriptRoot\..\backend"
python run.py
