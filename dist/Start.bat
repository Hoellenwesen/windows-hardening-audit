@echo off
REM Start.bat - checks prerequisites, then starts the app.
setlocal
set "OK=1"

if not exist "%ProgramFiles%\dotnet\shared\Microsoft.WindowsDesktop.App\10.*" (
  echo MISSING: .NET 10 Desktop Runtime x64 - see README.txt
  set "OK=0"
)

powershell -NoProfile -Command "if (-not (Get-AppxPackage -Name 'Microsoft.WindowsAppRuntime.*' -ErrorAction SilentlyContinue | Where-Object { $_.Version -like '2.5*' })) { exit 1 }" >nul 2>&1
if errorlevel 1 (
  echo MISSING: Windows App Runtime 2.5 - see README.txt
  set "OK=0"
)

if "%OK%"=="0" (
  echo.
  pause
  exit /b 1
)

start "" "%~dp0WinHardeningAudit.App.exe"
