@echo off
echo Starting Blockchain Application...
echo.

echo Installing Go dependencies...
go mod tidy

echo.
echo Starting Go backend server...
start "Blockchain Backend" cmd /k "go run main.go"

echo.
echo Waiting for backend to start...
timeout /t 3 /nobreak > nul

echo.
echo Installing React dependencies...
cd frontend
call npm install

echo.
echo Starting React frontend...
start "Blockchain Frontend" cmd /k "npm start"

echo.
echo Both servers are starting...
echo Backend: http://localhost:8080
echo Frontend: http://localhost:3000
echo.
echo Press any key to exit...
pause > nul
