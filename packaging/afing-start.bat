@echo off
rem Dat file nay CANH afing.exe roi bam dup. No chay giup lenh: afing.exe install-autostart
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

echo Dang ky tu chay cung Windows va chay afing ngay...
echo.
afing.exe install-autostart
echo.
pause
