# PyInstaller spec: gói afing thành file chạy được, không cần cài Python trên máy đích.
#   pyinstaller --noconfirm --clean packaging/afing.spec
# Kết quả: dist/afing.exe, và trên Windows thêm dist/afing-tray.exe (biểu tượng khay hệ thống).
import os
import sys

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(SPECPATH, "afing_exe.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "afing", "static"), os.path.join("afing", "static"))],  # dashboard
    excludes=["tkinter", "unittest", "pydoc", "scapy", "pystray", "PIL"],
)
exe = EXE(
    PYZ(a.pure), a.scripts, a.binaries, a.datas,
    name="afing",
    console=True,     # cần cửa sổ console để xem log và dùng các lệnh scan/dhcp/mdns
    upx=False,        # nén UPX hay làm phần mềm diệt virus báo nhầm
)

if sys.platform == "win32":
    t = Analysis(
        [os.path.join(SPECPATH, "afing_tray.py")],
        pathex=[ROOT],
        hiddenimports=["pystray._win32"],
        excludes=["tkinter", "unittest", "pydoc", "scapy"],
    )
    tray_exe = EXE(
        PYZ(t.pure), t.scripts, t.binaries, t.datas,
        name="afing-tray",
        console=False,  # chạy lúc đăng nhập, không được hiện cửa sổ đen
        upx=False,
    )
