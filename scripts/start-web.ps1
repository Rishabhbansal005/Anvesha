# Start PROJECT_NAME Web Investigation Workstation (Vite React)
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Starting PROJECT_NAME Web Workstation on Port 5173..." -ForegroundColor Green
Write-Host "URL: http://localhost:5173" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location -Path "$PSScriptRoot\..\web"
npm run dev
