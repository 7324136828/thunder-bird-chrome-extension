@echo off
rem Start the mail backend (mail-backend) on http://127.0.0.1:48101.
rem Double-click this file, or run:  run-backend.bat [--port PORT] [--addr HOST:PORT]
rem Keep the window open while you use the extension; close it to stop the backend.
rem Mailbox passwords are kept in memory only: stopping the backend locks every account.
setlocal
cd /d "%~dp0"
title mail-backend

where cargo >nul 2>nul
if %ERRORLEVEL%==0 (
  echo Building and starting mail-backend ^(the first build takes a few minutes^)...
  cargo run --release -p mail-backend -- %*
  goto :end
)

if exist "target\release\mail-backend.exe" (
  echo cargo not found - starting the previously built target\release\mail-backend.exe
  "target\release\mail-backend.exe" %*
  goto :end
)

echo.
echo Rust is not installed, so mail-backend cannot be built.
echo  1. Install Rust from https://rustup.rs  (accept the defaults)
echo  2. Open a NEW terminal and run this script again.
echo.
echo The mail extension needs this backend for every mailbox operation.

:end
echo.
echo mail-backend stopped.
pause
endlocal
