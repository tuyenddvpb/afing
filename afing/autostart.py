"""Tự chạy afing khi Windows khởi động, bằng một tác vụ trong Task Scheduler.

Tác vụ chạy dưới tài khoản SYSTEM ngay lúc máy bật (không cần ai đăng nhập), có sẵn quyền admin
nên nghe được DHCP, không hiện cửa sổ, tự chạy lại nếu bị lỗi và không bị giới hạn thời gian.
"""

import os
import subprocess
import sys
import tempfile
from typing import List, Tuple
from xml.sax.saxutils import escape

TASK_NAME = "afing"
TRAY_EXE = "afing-tray.exe"
TRAY_VALUE = "afing-tray"
RUN_KEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>afing - theo doi thiet bi trong mang LAN/Wi-Fi</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT20S</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def launch_command(extra_args: List[str], frozen: bool, executable: str, cwd: str) -> Tuple[str, str, str]:
    """(lệnh, tham số, thư mục làm việc) mà tác vụ sẽ chạy."""
    if frozen:  # bản .exe
        prefix, workdir = [], os.path.dirname(executable)
    else:       # chạy từ mã nguồn: python -m afing, tại thư mục chứa package
        prefix, workdir = ["-m", "afing"], cwd
    args = prefix + ["run", "--wait-network"] + extra_args
    return executable, " ".join(quote(a) for a in args), workdir


def build_xml(command: str, arguments: str, workdir: str) -> str:
    return TASK_XML.format(command=escape(command), arguments=escape(arguments),
                           workdir=escape(workdir))


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _schtasks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True, errors="replace")


def _precheck() -> str:
    if os.name != "nt":
        return "Lệnh này chỉ dùng trên Windows. Trên Linux hãy tạo một systemd service chạy afing."
    if not _is_admin():
        return ("Cần quyền admin: mở Command Prompt bằng \"Run as administrator\" rồi chạy lại "
                "lệnh này.")
    return ""


def install(extra_args: List[str], port: int) -> int:
    problem = _precheck()
    if problem:
        print("Lỗi: " + problem)
        return 1
    command, arguments, workdir = launch_command(
        extra_args, bool(getattr(sys, "frozen", False)), sys.executable, os.getcwd())
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-16") as f:
            f.write(build_xml(command, arguments, workdir))
        _schtasks("/End", "/TN", TASK_NAME)  # cài lại: dừng bản cũ để bản mới nhận cấu hình mới
        created = _schtasks("/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F")
    finally:
        os.unlink(xml_path)
    if created.returncode:
        print("Lỗi: không tạo được tác vụ.\n" + (created.stderr or created.stdout).strip())
        return 1
    print(f"Đã cài: afing sẽ tự chạy mỗi khi Windows khởi động.\n  Lệnh: {command} {arguments}")
    started = _schtasks("/Run", "/TN", TASK_NAME)
    if started.returncode:
        print("Chưa chạy được ngay (sẽ chạy ở lần khởi động tới): "
              + (started.stderr or started.stdout).strip())
    else:
        print(f"Đang chạy nền. Dashboard: http://localhost:{port}")
    tray = os.path.join(os.path.dirname(command), TRAY_EXE)
    if getattr(sys, "frozen", False) and os.path.exists(tray):
        # Biểu tượng khay hệ thống chạy trong phiên của người dùng, mỗi lần đăng nhập.
        added = subprocess.run(["reg", "add", RUN_KEY, "/v", TRAY_VALUE, "/t", "REG_SZ",
                                "/d", f'"{tray}"', "/f"], capture_output=True)
        if added.returncode == 0:
            # Tách hẳn khỏi tiến trình này: không thừa hưởng stdin/stdout, kẻo chương trình gọi
            # lệnh cài (bộ cài, script) phải chờ tới khi biểu tượng khay thoát.
            flags = getattr(subprocess, "DETACHED_PROCESS", 0) | \
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen([tray], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags)
            print("Đã bật biểu tượng afing ở khay hệ thống (cạnh đồng hồ).")
    print("Gỡ bỏ bằng lệnh: uninstall-autostart")
    return 0


def uninstall() -> int:
    problem = _precheck()
    if problem:
        print("Lỗi: " + problem)
        return 1
    _schtasks("/End", "/TN", TASK_NAME)  # dừng bản đang chạy nền, nếu có
    subprocess.run(["reg", "delete", RUN_KEY, "/v", TRAY_VALUE, "/f"], capture_output=True)
    subprocess.run(["taskkill", "/IM", TRAY_EXE, "/F"], capture_output=True)
    deleted = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if deleted.returncode:
        print("Lỗi: không gỡ được tác vụ (chưa từng cài?).\n"
              + (deleted.stderr or deleted.stdout).strip())
        return 1
    print("Đã gỡ: afing không còn tự chạy khi khởi động. Dữ liệu (afing.db) vẫn giữ nguyên.")
    return 0
