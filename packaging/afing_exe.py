"""Điểm vào cho bản đóng gói PyInstaller (xem packaging/afing.spec)."""

import sys

from afing.cli import main

if __name__ == "__main__":
    sys.exit(main())
