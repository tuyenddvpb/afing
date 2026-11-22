# PyInstaller spec: gói afing thành MỘT file chạy được, không cần cài Python trên máy đích.
#   pyinstaller --noconfirm --clean packaging/afing.spec      (kết quả: dist/afing.exe)
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(SPECPATH, "afing_exe.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "afing", "static"), os.path.join("afing", "static"))],  # dashboard
    excludes=["tkinter", "unittest", "pydoc", "scapy"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas,
    name="afing",
    console=True,     # cần cửa sổ console để xem log và dùng các lệnh scan/dhcp/mdns
    upx=False,        # nén UPX hay làm phần mềm diệt virus báo nhầm
)
