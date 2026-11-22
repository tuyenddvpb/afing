"""Bí danh tự động cho thiết bị: mỗi MAC được gán một loài vật trong rừng, dễ nhớ hơn dãy MAC.

Bí danh được chọn theo hàm băm của MAC nên cùng một thiết bị luôn "xin" cùng một con vật (kể cả
khi tạo lại database); nếu con đó đã có chủ thì lấy con kế tiếp còn trống. Hết danh sách thì
thêm số: "Hổ 2", "Hổ 3"...
"""

import hashlib
import re
from typing import Iterable, Optional

ANIMALS = [
    ("🐯", "Hổ"), ("🐆", "Báo"), ("🐻", "Gấu"), ("🐘", "Voi"), ("🐺", "Sói"), ("🦊", "Cáo"),
    ("🦌", "Hươu"), ("🫎", "Nai"), ("🐿️", "Sóc"), ("🐇", "Thỏ rừng"), ("🦔", "Nhím"), ("🐒", "Khỉ"),
    ("🦧", "Đười ươi"), ("🦍", "Khỉ đột"), ("🦉", "Cú"), ("🦅", "Đại bàng"), ("🦡", "Lửng"),
    ("🦦", "Rái cá"), ("🐗", "Lợn rừng"), ("🦚", "Công"), ("🐍", "Trăn"), ("🦎", "Tắc kè"),
    ("🦇", "Dơi"), ("🦜", "Vẹt"), ("🐢", "Rùa"), ("🐸", "Ếch"), ("🦋", "Bướm"), ("🐼", "Gấu trúc"),
    ("🦫", "Hải ly"), ("🦝", "Gấu mèo"), ("🦨", "Chồn"), ("🐦", "Chim sẻ"), ("🕊️", "Bồ câu"),
    ("🦏", "Tê giác"), ("🦬", "Bò rừng"), ("🐃", "Trâu rừng"), ("🦥", "Lười"), ("🐝", "Ong"),
    ("🐜", "Kiến"), ("🕷️", "Nhện"), ("🐞", "Bọ rùa"), ("🦗", "Dế"), ("🐌", "Ốc sên"),
    ("🐊", "Cá sấu"), ("🐓", "Gà rừng"), ("🦆", "Vịt trời"), ("🐁", "Chuột"), ("🐈", "Mèo rừng"),
    ("🐎", "Ngựa hoang"), ("🐐", "Sơn dương"), ("🪲", "Bọ hung"), ("🦂", "Bọ cạp"),
]
ICONS = {name: icon for icon, name in ANIMALS}


def pick(mac: str, used: Iterable[str]) -> str:
    """Chọn bí danh chưa ai dùng cho `mac`."""
    used = set(used)
    start = int(hashlib.sha1(mac.encode()).hexdigest()[:8], 16) % len(ANIMALS)
    round_ = 1
    while True:
        for i in range(len(ANIMALS)):
            name = ANIMALS[(start + i) % len(ANIMALS)][1]
            if round_ > 1:
                name = f"{name} {round_}"
            if name not in used:
                return name
        round_ += 1


def icon(alias: Optional[str]) -> str:
    """Emoji của bí danh ("Hổ 2" -> "🐯"); chuỗi rỗng nếu không rõ."""
    return ICONS.get(re.sub(r" \d+$", "", alias or ""), "")
