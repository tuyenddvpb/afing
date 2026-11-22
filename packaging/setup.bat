@echo off
rem Dat file nay CANH afing.exe (trong thu muc afing cua ban) roi bam dup de nang cap.
rem No chi chay giup 2 lenh: "afing.exe uninstall-autostart" va "afing.exe install-autostart",
rem dung lai o giua de ban tu chep afing.exe moi vao. Khong chep hay xoa file nao.
setlocal

rem --- Can quyen admin: tu mo lai chinh no voi quyen admin (hien hop thoai UAC) ---
net session >nul 2>&1
if errorlevel 1 (
  echo Dang xin quyen admin...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
if not exist afing.exe (
  echo Khong thay afing.exe trong thu muc nay: %CD%
  echo Hay dat setup.bat canh afing.exe.
  goto :fail
)

echo [1/3] Dung ban afing dang chay nen...
afing.exe uninstall-autostart

echo.
echo [2/3] Bay gio hay chep afing.exe va afing-tray.exe MOI vao thu muc:
echo       %CD%
echo       Chep xong thi quay lai cua so nay va nhan phim bat ky.
echo       Khong co ban moi thi cu nhan phim de chay lai ban hien tai.
pause >nul

echo.
echo [3/3] Dang ky tu chay cung Windows va chay ngay...
afing.exe install-autostart
if errorlevel 1 goto :fail

echo.
echo Xong. afing dang chay nen; mo dashboard bang bieu tuong afing canh dong ho.
pause
exit /b 0

:fail
echo.
echo That bai.
pause
exit /b 1
