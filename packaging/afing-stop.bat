@echo off
rem Dat file nay CANH afing.exe roi bam dup. No chay giup lenh: afing.exe uninstall-autostart
setlocal

rem Can quyen admin: tu mo lai chinh no voi quyen admin (hien hop thoai UAC).
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
if not exist afing.exe (
  echo Khong thay afing.exe trong thu muc nay: %CD%
  echo Hay dat file nay canh afing.exe.
  pause
  exit /b 1
)

echo Dung afing dang chay nen va tat tu chay cung Windows...
echo.
afing.exe uninstall-autostart
echo.
pause
