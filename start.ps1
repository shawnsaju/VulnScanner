# VulnScanner Quick Start Script
# Run this from the VulnScanner root directory
# Usage: .\start.ps1

Write-Host "🔒 Starting VulnScanner..." -ForegroundColor Cyan

# Start backend in new terminal window
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Write-Host '🐍 Backend starting...' -ForegroundColor Green; cd '$PSScriptRoot\backend'; python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
)

# Short delay before starting frontend
Start-Sleep -Seconds 2

# Start frontend in new terminal window
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Write-Host '⚛️  Frontend starting...' -ForegroundColor Blue; cd '$PSScriptRoot\frontend'; npm run dev"
)

# Wait for servers to start
Start-Sleep -Seconds 4

# Open browser
Write-Host "🌐 Opening browser..." -ForegroundColor Green
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "✅ VulnScanner is running!" -ForegroundColor Green
Write-Host "   Frontend: http://localhost:5173" -ForegroundColor Cyan
Write-Host "   Backend:  http://localhost:8000" -ForegroundColor Cyan
Write-Host "   API Docs: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit this launcher..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
