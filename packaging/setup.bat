@echo off
rem Cai hoac nang cap afing bang cac file exe nam canh file nay (thu muc dist).
rem Lam lan luot: go ban dang chay nen -> chep afing.exe + afing-tray.exe vao thu muc cai dat
rem -> dang ky tu chay cung Windows va chay ngay. afing.cfg va afing.db duoc giu nguyen.
setlocal

rem --- Can quyen admin: tu mo lai chinh no voi quyen admin (hien hop thoai UAC) ---
net session >nul 2>&1
if errorlevel 1 (
  echo Dang xin quyen admin...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "SRC=%~dp0"
set "SRCDIR=%SRC:~0,-1%"
if not exist "%SRC%afing.exe" (
  echo Khong thay afing.exe canh file nay. Hay chay build_exe.bat truoc.
  goto :fail
)

rem --- Chon thu muc cai dat (nho lai cho lan sau trong setup-target.txt) ---
set "TARGET="
set "ANS="
if exist "%SRC%setup-target.txt" set /p TARGET=<"%SRC%setup-target.txt"
if defined TARGET goto :ask_keep
set /p "ANS=Thu muc cai afing (nhan Enter de dung %SRCDIR%): "
goto :asked
:ask_keep
echo Thu muc cai dat lan truoc: %TARGET%
set /p "ANS=Nhan Enter de dung lai, hoac go thu muc khac: "
:asked
if defined ANS set "TARGET=%ANS%"
if not defined TARGET set "TARGET=%SRCDIR%"
set "TARGET=%TARGET:"=%"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
if not exist "%TARGET%\" mkdir "%TARGET%"
if not exist "%TARGET%\" (
  echo Khong tao duoc thu muc "%TARGET%".
  goto :fail
)
>"%SRC%setup-target.txt" echo %TARGET%
echo.
echo Cai afing vao: %TARGET%
echo.

rem --- 1. Go ban cu dang chay nen (neu co) de nha file exe ---
if exist "%TARGET%\afing.exe" (
  echo [1/3] Dung ban afing dang chay...
  "%TARGET%\afing.exe" uninstall-autostart
) else (
  echo [1/3] Chua co ban cu, bo qua.
)

rem --- 2. Chep file moi (bo qua neu cai ngay tai thu muc nay) ---
if /I "%TARGET%"=="%SRCDIR%" (
  echo [2/3] Cai tai cho, khong can chep file.
) else (
  echo [2/3] Chep file moi...
  copy /Y "%SRC%afing.exe" "%TARGET%\afing.exe" >nul || goto :copyfail
  if exist "%SRC%afing-tray.exe" copy /Y "%SRC%afing-tray.exe" "%TARGET%\afing-tray.exe" >nul || goto :copyfail
)

rem --- 3. Dang ky tu chay va chay ngay ---
echo [3/3] Dang ky tu chay cung Windows...
"%TARGET%\afing.exe" install-autostart
if errorlevel 1 goto :fail

echo.
echo Xong. afing dang chay nen; mo dashboard bang bieu tuong afing canh dong ho.
pause
exit /b 0

:copyfail
echo Khong chep duoc file vao "%TARGET%". File cu con dang chay?
:fail
echo.
echo Cai dat that bai.
pause
exit /b 1
