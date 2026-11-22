@echo off
rem Build dist\afing.exe tren Windows. Yeu cau: da cai Python 3.9+ (co pip).
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :error
python -m PyInstaller --noconfirm --clean packaging\afing.spec || goto :error
echo.
echo Xong: dist\afing.exe
exit /b 0
:error
echo.
echo Build that bai.
exit /b 1
