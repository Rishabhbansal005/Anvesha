# Start PROJECT_NAME Mobile Companion Application (Expo React Native)
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Starting PROJECT_NAME Mobile Companion (Expo)..." -ForegroundColor Green
Write-Host "Metro Bundler: http://localhost:8081" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location -Path "$PSScriptRoot\..\mobile"
npx expo start
