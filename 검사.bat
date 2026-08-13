@echo off
chcp 65001 >nul
cd /d "%~dp0"
node "보안검사.js"
echo.
pause
