"""Bí danh tự động cho thiết bị: mỗi MAC được gán một loài vật trong rừng, dễ nhớ hơn dãy MAC.

Bí danh được chọn theo hàm băm của MAC nên cùng một thiết bị luôn "xin" cùng một con vật (kể cả
khi tạo lại database); nếu con đó đã có chủ thì lấy con kế tiếp còn trống. Không bao giờ có hai
thiết bị chung một bí danh. Có 100 loài (52 loài rừng, rồi 48 loài khác); chỉ khi hết cả 100
mới phải thêm số: "Tiger 2", "Tiger 3"...
"""

import hashlib
import re
from typing import Iterable, Optional

# (emoji, bí danh, tên tiếng Việt mà các bản afing cũ đã lưu vào database)
ANIMALS = [
    ("🐯", "Tiger", "Hổ"), ("🐆", "Leopard", "Báo"), ("🐻", "Bear", "Gấu"), ("🐘", "Elephant", "Voi"),
    ("🐺", "Wolf", "Sói"), ("🦊", "Fox", "Cáo"), ("🦌", "Deer", "Hươu"), ("🫎", "Moose", "Nai"),
    ("🐿️", "Squirrel", "Sóc"), ("🐇", "Hare", "Thỏ rừng"), ("🦔", "Hedgehog", "Nhím"),
    ("🐒", "Monkey", "Khỉ"), ("🦧", "Orangutan", "Đười ươi"), ("🦍", "Gorilla", "Khỉ đột"),
    ("🦉", "Owl", "Cú"), ("🦅", "Eagle", "Đại bàng"), ("🦡", "Badger", "Lửng"),
    ("🦦", "Otter", "Rái cá"), ("🐗", "Boar", "Lợn rừng"), ("🦚", "Peacock", "Công"),
    ("🐍", "Python", "Trăn"), ("🦎", "Gecko", "Tắc kè"), ("🦇", "Bat", "Dơi"),
    ("🦜", "Parrot", "Vẹt"), ("🐢", "Turtle", "Rùa"), ("🐸", "Frog", "Ếch"),
    ("🦋", "Butterfly", "Bướm"), ("🐼", "Panda", "Gấu trúc"), ("🦫", "Beaver", "Hải ly"),
    ("🦝", "Raccoon", "Gấu mèo"), ("🦨", "Skunk", "Chồn"), ("🐦", "Sparrow", "Chim sẻ"),
    ("🕊️", "Dove", "Bồ câu"), ("🦏", "Rhino", "Tê giác"), ("🦬", "Bison", "Bò rừng"),
    ("🐃", "Buffalo", "Trâu rừng"), ("🦥", "Sloth", "Lười"), ("🐝", "Bee", "Ong"),
    ("🐜", "Ant", "Kiến"), ("🕷️", "Spider", "Nhện"), ("🐞", "Ladybug", "Bọ rùa"),
    ("🦗", "Cricket", "Dế"), ("🐌", "Snail", "Ốc sên"), ("🐊", "Crocodile", "Cá sấu"),
    ("🐓", "Junglefowl", "Gà rừng"), ("🦆", "Duck", "Vịt trời"), ("🐁", "Mouse", "Chuột"),
    ("🐈", "Wildcat", "Mèo rừng"), ("🐎", "Mustang", "Ngựa hoang"), ("🐐", "Ibex", "Sơn dương"),
    ("🪲", "Beetle", "Bọ hung"), ("🦂", "Scorpion", "Bọ cạp"),
]
# Dùng khi 52 loài trong rừng ở trên đã có chủ hết: các loài khác, vẫn mỗi loài một emoji riêng.
EXTRA = [
    ("🦁", "Lion"), ("🦓", "Zebra"), ("🦒", "Giraffe"), ("🦛", "Hippo"), ("🐪", "Camel"),
    ("🦘", "Kangaroo"), ("🐨", "Koala"), ("🦙", "Llama"), ("🦩", "Flamingo"), ("🦢", "Swan"),
    ("🐧", "Penguin"), ("🦭", "Seal"), ("🐬", "Dolphin"), ("🐳", "Whale"), ("🦈", "Shark"),
    ("🐙", "Octopus"), ("🦀", "Crab"), ("🦞", "Lobster"), ("🦑", "Squid"), ("🪼", "Jellyfish"),
    ("🦐", "Shrimp"), ("🐡", "Pufferfish"), ("🐠", "Angelfish"), ("🐟", "Trout"), ("🦤", "Dodo"),
    ("🦣", "Mammoth"), ("🦃", "Turkey"), ("🪿", "Goose"), ("🐥", "Chick"), ("🐛", "Caterpillar"),
    ("🦟", "Mosquito"), ("🪱", "Worm"), ("🪰", "Fly"), ("🐹", "Hamster"), ("🐰", "Rabbit"),
    ("🐏", "Ram"), ("🐂", "Ox"), ("🫏", "Donkey"), ("🦪", "Oyster"), ("🐉", "Dragon"),
    ("🦖", "Tyrannosaur"), ("🦕", "Brontosaur"), ("🦄", "Unicorn"), ("🐋", "Humpback"), ("🐀", "Rat"),
    ("🐑", "Sheep"), ("🐖", "Pig"), ("🐄", "Cow"),
]
ICONS = {name: icon for icon, name, _ in ANIMALS}
ICONS.update({name: icon for icon, name in EXTRA})
LEGACY = {old: name for _, name, old in ANIMALS}


def pick(mac: str, used: Iterable[str]) -> str:
    """Chọn bí danh chưa ai dùng cho `mac`."""
    used = set(used)
    seed = int(hashlib.sha1(mac.encode()).hexdigest()[:8], 16)
    for pool in ([a[1] for a in ANIMALS], [a[1] for a in EXTRA]):
        for i in range(len(pool)):
            name = pool[(seed + i) % len(pool)]
            if name not in used:
                return name
    # Hơn 100 thiết bị: hết loài để gán, buộc phải đánh số. Tên vẫn không trùng nhau.
    pool = [a[1] for a in ANIMALS]
    round_ = 2
    while True:
        for i in range(len(pool)):
            name = f"{pool[(seed + i) % len(pool)]} {round_}"
            if name not in used:
                return name
        round_ += 1


def _split(alias: str):
    m = re.fullmatch(r"(.*?)( \d+)?", alias)
    return m.group(1), m.group(2) or ""


def icon(alias: Optional[str]) -> str:
    """Emoji của bí danh ("Tiger 2" -> "🐯"); chuỗi rỗng nếu không rõ."""
    return ICONS.get(_split(alias or "")[0], "")


def from_legacy(alias: Optional[str]) -> Optional[str]:
    """Đổi bí danh tiếng Việt của bản cũ sang tên hiện tại ("Hổ 2" -> "Tiger 2"); None nếu không phải."""
    base, number = _split(alias or "")
    return LEGACY[base] + number if base in LEGACY else None
