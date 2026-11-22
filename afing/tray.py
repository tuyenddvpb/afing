"""Biểu tượng afing ở khay hệ thống Windows (cạnh đồng hồ).

Chạy trong phiên của người dùng, tách khỏi bản quét chạy nền: nó chỉ hỏi dashboard để hiện số
thiết bị đang online và cho mở dashboard bằng một cú bấm. Cần hai thư viện `pystray` và
`Pillow`, đã được đóng gói sẵn trong afing-tray.exe.
"""

import base64
import json
import threading
import urllib.request
import webbrowser
from typing import Optional, Tuple

from . import config


def dashboard(config_path: str) -> Tuple[str, Optional[str]]:
    """(địa chỉ dashboard, mật khẩu nếu có) theo afing.cfg."""
    try:
        cfg = config.load(config_path)
        port, host, password = cfg[("web", "port")], cfg[("web", "host")], cfg[("web", "password")]
    except config.ConfigError:
        port, host, password = 8080, "127.0.0.1", ""
    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0", "") else host
    return f"http://{shown}:{port}", password or None


def fetch_summary(url: str, password: Optional[str], timeout: float = 4) -> Optional[dict]:
    """Số thiết bị online/tổng/lạ từ dashboard; None nếu afing không chạy."""
    req = urllib.request.Request(url + "/api/state")
    if password:
        req.add_header("Authorization",
                       "Basic " + base64.b64encode(f"tray:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            devices = json.load(resp).get("devices", [])
    except Exception:
        return None
    return {"online": sum(1 for d in devices if d.get("is_online")), "total": len(devices),
            "unknown": sum(1 for d in devices if not d.get("known"))}


def tooltip(summary: Optional[dict]) -> str:
    if summary is None:
        return "afing: not running"
    text = f"afing: {summary['online']} online / {summary['total']} devices"
    return text + (f", {summary['unknown']} unknown" if summary["unknown"] else "")


def make_image(running: bool = True):
    """Vẽ biểu tượng 64x64: ba vòng cung sóng trên nền xanh (xám khi afing không chạy)."""
    from PIL import Image, ImageDraw
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((2, 2, 62, 62), radius=14, fill=(11, 107, 203) if running else (120, 128, 138))
    for radius in (34, 24, 14):
        draw.arc((32 - radius, 46 - radius, 32 + radius, 46 + radius), 215, 325, fill="white", width=5)
    draw.ellipse((27, 41, 37, 51), fill="white")
    return image


def run(config_path: str, self_test: bool = False) -> int:
    """Hiện biểu tượng và chạy cho tới khi người dùng chọn Exit. `self_test`: tự thoát sau 3 giây."""
    import pystray

    url, password = dashboard(config_path)
    state = {"summary": fetch_summary(url, password)}
    stop = threading.Event()

    def open_dashboard(icon=None, item=None):
        webbrowser.open(url)

    def quit_tray(icon, item=None):
        stop.set()
        icon.stop()

    icon = pystray.Icon(
        "afing", make_image(state["summary"] is not None), tooltip(state["summary"]),
        menu=pystray.Menu(
            pystray.MenuItem("Open dashboard", open_dashboard, default=True),
            pystray.MenuItem(lambda item: tooltip(state["summary"]), None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", quit_tray),
        ))

    def refresh():
        while not stop.wait(10):
            new = fetch_summary(url, password)
            if (new is None) != (state["summary"] is None):
                icon.icon = make_image(new is not None)
            state["summary"] = new
            icon.title = tooltip(new)
            icon.update_menu()

    threading.Thread(target=refresh, daemon=True).start()
    if self_test:
        threading.Timer(3.0, lambda: quit_tray(icon)).start()
    icon.run()
    return 0
