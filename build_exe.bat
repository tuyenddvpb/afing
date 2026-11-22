@echo off
rem Build afing tren Windows. Yeu cau: Python 3.9+ (co pip).
rem Ket qua trong thu muc dist:
rem   afing.exe        chuong trinh chinh
rem   afing-tray.exe   bieu tuong khay he thong
rem   afing-setup.exe  bo cai (chi tao khi may co Inno Setup 6: https://jrsoftware.org/isdl.php)
cd /d "%~dp0"

python -m pip install --upgrade pyinstaller pystray pillow || goto :error
python -m unittest discover -s tests || goto :error
python -m PyInstaller --noconfirm --clean packaging\afing.spec || goto :error

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if exist "%ISCC%" (
  for /f "delims=" %%v in ('python -c "import afing; print(afing.__version__)"') do set "AFING_VERSION=%%v"
  call "%ISCC%" "/DAppVersion=%AFING_VERSION%" packaging\afing.iss || goto :error
) else (
  echo.
  echo Khong thay Inno Setup 6 nen bo qua buoc tao bo cai afing-setup.exe.
)

echo.
echo Xong. Cac file nam trong thu muc dist:
dir /b dist\*.exe
exit /b 0

:error
echo.
echo Build that bai.
exit /b 1
