"""Kiểm tra và cài bản afing mới từ GitHub Releases.

Chỉ tải từ đúng kho mã của afing qua HTTPS, và chỉ cài khi file tải về khớp mã SHA-256 mà bản
phát hành công bố kèm theo.
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Optional, Tuple

from . import __version__

log = logging.getLogger("afing.update")

REPO = "tuyenddvpb/afing"
API = "https://api.github.com"
ASSET = "afing.exe"
ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com")


def parse_version(text: str) -> Tuple[int, ...]:
    """"v1.2.3" -> (1, 2, 3). Chuỗi lạ -> () (coi là cũ hơn mọi bản)."""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", (text or "").strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else ()


def is_newer(latest: str, current: str = __version__) -> bool:
    a, b = parse_version(latest), parse_version(current)
    return bool(a) and a > b


def _get(url: str, timeout: float = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "afing-updater",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_release() -> Optional[dict]:
    """Bản phát hành mới nhất: {"version", "url" (trang), "exe", "sha256" (link tải)}; None nếu chưa có."""
    try:
        data = json.loads(_get(f"{API}/repos/{REPO}/releases/latest"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # kho chưa có bản phát hành nào
        raise
    assets = {a.get("name"): a.get("browser_download_url") for a in data.get("assets", [])}
    return {"version": (data.get("tag_name") or "").lstrip("v"), "url": data.get("html_url"),
            "exe": assets.get(ASSET), "sha256": assets.get(ASSET + ".sha256")}


def check() -> Optional[dict]:
    """Có bản mới hơn bản đang chạy thì trả thông tin bản đó, không thì None. Không ném lỗi mạng."""
    try:
        release = latest_release()
    except Exception as e:
        log.debug("Không kiểm tra được bản mới: %s", e)
        return None
    return release if release and is_newer(release["version"]) else None


def _allowed(url: Optional[str]) -> bool:
    """Chỉ tải từ máy chủ của GitHub, qua HTTPS."""
    m = re.match(r"https://([^/:]+)/", url or "")
    return bool(m) and m.group(1) in ALLOWED_HOSTS


def download_verified(release: dict, target: str) -> None:
    """Tải file exe của bản phát hành về `target`, chỉ giữ lại nếu khớp SHA-256."""
    if not _allowed(release.get("exe")):
        raise RuntimeError("bản phát hành không có file afing.exe hợp lệ")
    if not _allowed(release.get("sha256")):
        raise RuntimeError("bản phát hành không kèm mã SHA-256 nên không thể xác minh")
    expected = _get(release["sha256"]).decode("ascii", "replace").split()[0].lower()
    data = _get(release["exe"], timeout=120)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise RuntimeError("file tải về không khớp mã SHA-256 - đã huỷ")
    with open(target, "wb") as f:
        f.write(data)


def install(out=print) -> int:
    """Lệnh `update`: tải bản mới và thay cho file exe đang chạy."""
    if not getattr(sys, "frozen", False):
        out("Lệnh update chỉ dùng cho bản afing.exe. Chạy từ mã nguồn thì dùng: git pull")
        return 1
    out(f"Bản đang dùng: {__version__}. Đang kiểm tra bản mới...")
    try:
        release = latest_release()
    except Exception as e:
        out(f"Lỗi: không kiểm tra được ({e}).")
        return 1
    if not release:
        out("Chưa có bản phát hành nào.")
        return 0
    if not is_newer(release["version"]):
        out(f"Bạn đang dùng bản mới nhất ({__version__}).")
        return 0
    exe = os.path.abspath(sys.executable)
    new, old = exe + ".new", exe + ".old"
    out(f"Đang tải bản {release['version']}...")
    try:
        download_verified(release, new)
        if os.path.exists(old):
            os.remove(old)
        # Windows không cho ghi đè file exe đang chạy nhưng cho đổi tên nó.
        os.replace(exe, old)
        os.replace(new, exe)
    except Exception as e:
        out(f"Lỗi: cập nhật thất bại ({e}). Bản hiện tại vẫn giữ nguyên.")
        if os.path.exists(new):
            os.remove(new)
        if not os.path.exists(exe) and os.path.exists(old):
            os.replace(old, exe)
        return 1
    out(f"Đã cập nhật lên bản {release['version']}.")
    # Bản chạy nền (nếu có) vẫn là bản cũ cho tới khi được khởi động lại.
    from . import autostart
    if os.name == "nt" and autostart._schtasks("/Query", "/TN", autostart.TASK_NAME).returncode == 0:
        if autostart._is_admin():
            autostart._schtasks("/End", "/TN", autostart.TASK_NAME)
            autostart._schtasks("/Run", "/TN", autostart.TASK_NAME)
            out("Đã khởi động lại bản chạy nền.")
        else:
            out("Bản chạy nền sẽ dùng bản mới sau khi khởi động lại máy "
                "(hoặc chạy lại install-autostart bằng quyền admin).")
    return 0
