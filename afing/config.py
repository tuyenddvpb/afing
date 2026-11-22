"""File cấu hình afing.cfg: mọi thiết lập ở một chỗ, sửa bằng Notepad.

Thứ tự ưu tiên: tham số dòng lệnh > afing.cfg > giá trị mặc định.
File nằm cạnh afing.exe (bản đóng gói) hoặc ở thư mục đang đứng (chạy từ mã nguồn), và được tự
tạo với giá trị mặc định ở lần chạy đầu.
"""

import configparser
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

FILE_NAME = "afing.cfg"

TEMPLATE = """\
# afing.cfg - cấu hình afing.
# Sửa xong thì khởi động lại afing để áp dụng (bản tự chạy nền: chạy lại lệnh
# install-autostart, hoặc khởi động lại máy). Riêng mục [notify] được áp dụng ngay.
# Tham số trên dòng lệnh, nếu có, được ưu tiên hơn file này.

[web]
# Cổng của dashboard: http://localhost:<port>
port = 8080
# 127.0.0.1 = chỉ máy này xem được dashboard. 0.0.0.0 = mọi máy trong mạng LAN xem được.
host = 127.0.0.1
# Tự mở dashboard bằng trình duyệt khi bấm đúp afing.exe (yes/no)
open_browser = yes
# no = chỉ quét và ghi database, không chạy dashboard
enabled = yes
# Mật khẩu để mở dashboard (tên đăng nhập gõ gì cũng được). Để trống = không cần mật khẩu.
# Nên đặt khi host = 0.0.0.0.
password =
# Ngôn ngữ của dashboard và của tin nhắn/báo cáo: en | vi
language = en
# Mỗi ngày hỏi GitHub một lần xem có bản afing mới không, và báo trên dashboard (yes/no).
# afing không tự cài; cài bằng lệnh: afing.exe update
update_check = yes

[scan]
# Dải mạng cần quét, ví dụ 192.168.1.0/24. Để trống = tự dò theo mạng máy đang nối.
subnet =
# Số giây giữa hai lượt quét
interval = 10
# Không thấy thiết bị quá số giây này thì coi là đã rời mạng
offline_after = 45
# auto | arp (cần scapy + quyền admin) | passive
method = auto
# Nghe gói DHCP để lấy tên thiết bị (cần quyền admin) (yes/no)
dhcp = yes
# Tự tải bảng hãng sản xuất từ IEEE ở lần chạy đầu (yes/no)
oui_download = yes

[data]
# File database. Để trống = afing.db cạnh file cấu hình này.
database =
# File log. Để trống = không ghi log ra file.
log_file =

[notify]
# Thông báo ra điện thoại. Điền tự động bằng lệnh notify-setup, hoặc tự điền tại đây.
telegram_token =
telegram_chat_id =
ntfy_topic =
ntfy_server = https://ntfy.sh
# Thiết bị vắng mặt liên tục bấy nhiêu phút mới báo "rời mạng"
leave_after_minutes = 5
# Báo khi có thiết bị chưa từng thấy vào mạng (yes/no)
new_device_alerts = yes
# Báo rời mạng / quay lại cho: all = mọi thiết bị | unknown = chỉ thiết bị chưa đánh dấu
# "quen" | none = không báo. Từng thiết bị có thể đặt riêng trên dashboard.
presence_alerts = all
# Giờ yên lặng: không báo rời mạng / quay lại trong khoảng này, ví dụ 23:00-07:00.
# Thiết bị lạ mới vào mạng vẫn được báo. Để trống = không có giờ yên lặng.
quiet_hours =

[report]
# Báo cáo danh sách thiết bị online/offline, gửi qua kênh đã đặt ở mục [notify].
# Gửi vào các giờ cố định mỗi ngày (giờ của máy chạy afing), cách nhau bằng dấu phẩy.
# Ví dụ: 08:00, 12:30, 21:00. Để trống = không gửi theo giờ.
times =
# Hoặc gửi lặp lại sau mỗi bấy nhiêu phút (ví dụ 60 = mỗi giờ). 0 = tắt.
interval_minutes = 0
# Chỉ liệt kê thiết bị offline được thấy trong bấy nhiêu ngày gần đây. 0 = liệt kê tất cả.
offline_days = 7
# Nhắn /report, /online, /offline cho bot Telegram để nhận báo cáo ngay (yes/no)
telegram_commands = yes
"""

# (mục, khoá) -> kiểu. Giá trị mặc định lấy từ TEMPLATE để không phải khai hai nơi.
KINDS: Dict[Tuple[str, str], str] = {
    ("web", "port"): "port", ("web", "host"): "str", ("web", "open_browser"): "bool",
    ("web", "enabled"): "bool", ("web", "password"): "str", ("web", "language"): "choice:en,vi",
    ("web", "update_check"): "bool",
    ("scan", "subnet"): "str", ("scan", "interval"): "positive", ("scan", "offline_after"): "positive",
    ("scan", "method"): "choice:auto,arp,passive", ("scan", "dhcp"): "bool", ("scan", "oui_download"): "bool",
    ("data", "database"): "str", ("data", "log_file"): "str",
    ("notify", "telegram_token"): "str", ("notify", "telegram_chat_id"): "str",
    ("notify", "ntfy_topic"): "str", ("notify", "ntfy_server"): "str",
    ("notify", "leave_after_minutes"): "number", ("notify", "new_device_alerts"): "bool",
    ("notify", "presence_alerts"): "choice:all,unknown,none", ("notify", "quiet_hours"): "hours",
    ("report", "times"): "times", ("report", "interval_minutes"): "nonneg",
    ("report", "offline_days"): "nonneg", ("report", "telegram_commands"): "bool",
}
_BOOLS = {"yes": True, "true": True, "on": True, "1": True,
          "no": False, "false": False, "off": False, "0": False}


class ConfigError(ValueError):
    pass


def app_dir() -> str:
    """Thư mục chứa afing.exe (bản đóng gói) hoặc thư mục hiện tại."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.getcwd()


def default_path() -> str:
    return os.path.join(app_dir(), FILE_NAME)


def _parser() -> configparser.ConfigParser:
    return configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None)


def _convert(section: str, key: str, raw: str, name: str):
    kind = KINDS[(section, key)]
    raw = raw.strip()
    where = f"{name}: [{section}] {key} = {raw!r}"
    if kind == "str":
        return raw
    if kind == "bool":
        if raw.lower() not in _BOOLS:
            raise ConfigError(f"{where} phải là yes hoặc no")
        return _BOOLS[raw.lower()]
    if kind.startswith("choice:"):
        options = kind[7:].split(",")
        if raw.lower() not in options:
            raise ConfigError(f"{where} phải là một trong: {', '.join(options)}")
        return raw.lower()
    if kind == "hours":
        if not raw:
            return None
        m = re.fullmatch(r"(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})", raw)
        if not m or int(m[1]) > 23 or int(m[3]) > 23 or int(m[2]) > 59 or int(m[4]) > 59:
            raise ConfigError(f"{where} phải có dạng 23:00-07:00")
        return (int(m[1]) * 60 + int(m[2]), int(m[3]) * 60 + int(m[4]))
    if kind == "times":
        times = []
        for part in filter(None, (p.strip() for p in raw.split(","))):
            m = re.fullmatch(r"(\d{1,2})[:hH](\d{2})", part)
            if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
                raise ConfigError(f"{where}: {part!r} phải có dạng giờ:phút, ví dụ 08:00")
            times.append((int(m.group(1)), int(m.group(2))))
        return times
    try:
        value = float(raw) if kind in ("number", "nonneg") else int(raw)
    except ValueError:
        raise ConfigError(f"{where} phải là một số") from None
    if kind == "port" and not 1 <= value <= 65535:
        raise ConfigError(f"{where} phải nằm trong khoảng 1-65535")
    if kind in ("positive", "number") and value <= 0:
        raise ConfigError(f"{where} phải lớn hơn 0")
    if kind == "nonneg" and value < 0:
        raise ConfigError(f"{where} không được âm")
    return value


class Config:
    def __init__(self, path: str, values: Dict[Tuple[str, str], object]):
        self.path = os.path.abspath(path)
        self.dir = os.path.dirname(self.path)
        self.values = values

    def __getitem__(self, section_key: Tuple[str, str]):
        return self.values[section_key]

    def resolve(self, value: str) -> str:
        """Đường dẫn tương đối trong file cấu hình được tính từ thư mục chứa file đó."""
        return value if os.path.isabs(value) else os.path.join(self.dir, value)


def load(path: str) -> Config:
    """Đọc cấu hình; file không tồn tại thì dùng toàn giá trị mặc định."""
    defaults = _parser()
    defaults.read_string(TEMPLATE)
    user = _parser()
    name = os.path.basename(path)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8-sig") as f:  # Notepad hay thêm BOM
                user.read_file(f)
        except (configparser.Error, UnicodeDecodeError) as e:
            raise ConfigError(f"{name}: không đọc được ({str(e).splitlines()[0]})") from None
    values = {}
    for section, key in KINDS:
        raw = user.get(section, key, fallback=None)
        if raw is None:
            raw = defaults.get(section, key)
        values[(section, key)] = _convert(section, key, raw, name)
    return Config(path, values)


def ensure(path: str) -> bool:
    """Tạo file cấu hình mẫu nếu chưa có. Trả True nếu vừa tạo."""
    if os.path.exists(path):
        return False
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(TEMPLATE)
    return True


def _template_sections() -> Dict[str, List[Tuple[str, str]]]:
    """Mẫu cấu hình tách thành {mục: [(khoá, các dòng chú thích + dòng khoá)]}."""
    sections: Dict[str, List[Tuple[str, str]]] = {}
    current, pending = None, []
    for line in TEMPLATE.split("\n"):
        header = re.fullmatch(r"\[(\w+)\]", line.strip())
        if header:
            current, pending = header.group(1), []
            sections[current] = []
        elif current and line.startswith("#"):
            pending.append(line)
        elif current and "=" in line:
            sections[current].append((line.split("=")[0].strip(), "\n".join(pending + [line])))
            pending = []
    return sections


def upgrade(path: str) -> List[str]:
    """Thêm vào file cấu hình cũ những mục và khoá mà bản afing mới có, kèm chú thích.

    Không đụng tới giá trị hay chú thích sẵn có. Trả danh sách "[mục]" / "mục.khoá" đã thêm.
    """
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig") as f:
        lines = f.read().split("\n")
    added = []
    for section, entries in _template_sections().items():
        start = next((i for i, line in enumerate(lines)
                      if line.strip().lower() == f"[{section}]"), None)
        if start is None:
            while lines and not lines[-1].strip():
                lines.pop()
            lines += ["", f"[{section}]"] + [block for _, block in entries] + [""]
            added.append(f"[{section}]")
            continue
        end = next((i for i in range(start + 1, len(lines))
                    if re.match(r"\s*\[.*\]\s*$", lines[i])), len(lines))
        have = {line.split("=")[0].split(":")[0].strip().lower()
                for line in lines[start + 1:end] if not line.lstrip().startswith(("#", ";"))}
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1
        for key, block in entries:
            if key.lower() not in have:
                lines[end:end] = block.split("\n")
                end += block.count("\n") + 1
                added.append(f"{section}.{key}")
    if added:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
        os.replace(tmp, path)
    return added


def set_values(path: str, section: str, values: Dict[str, object]) -> None:
    """Ghi vài khoá vào file cấu hình mà vẫn giữ nguyên chú thích và các dòng khác."""
    ensure(path)
    with open(path, encoding="utf-8-sig") as f:
        lines = f.read().split("\n")
    for key, value in values.items():
        if isinstance(value, bool):
            value = "yes" if value else "no"
        new_line = f"{key} = {value}".rstrip()
        start = next((i for i, line in enumerate(lines)
                      if line.strip().lower() == f"[{section}]"), None)
        if start is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines += [f"[{section}]", new_line]
            continue
        end = next((i for i in range(start + 1, len(lines))
                    if re.match(r"\s*\[.*\]\s*$", lines[i])), len(lines))
        pattern = re.compile(r"\s*" + re.escape(key) + r"\s*[=:]", re.I)
        found = next((i for i in range(start + 1, end) if pattern.match(lines[i])), None)
        if found is not None:
            lines[found] = new_line
        else:
            while end > start + 1 and not lines[end - 1].strip():
                end -= 1  # chèn ngay sau dòng có nội dung cuối cùng của mục
            lines.insert(end, new_line)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    os.replace(tmp, path)
