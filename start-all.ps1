Write-Host "Starting SupplyGraph Backend (FastAPI)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit -Command `"cd backend; .\venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload`""

Write-Host "Starting SupplyGraph Frontend (Next.js)..." -ForegroundColor Magenta
Start-Process -FilePath "powershell" -ArgumentList "-NoExit -Command `"cd frontend; npm run dev`""

Write-Host "SupplyGraph is starting up!" -ForegroundColor Green
Write-Host "Backend API: http://127.0.0.1:8000/docs" -ForegroundColor Yellow
Write-Host "Frontend UI: http://localhost:3000" -ForegroundColor Yellow
