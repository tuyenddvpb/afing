"""Điểm vào của afing-tray.exe: biểu tượng khay hệ thống, không có cửa sổ console."""

import sys

from afing import config, tray

if __name__ == "__main__":
    sys.exit(tray.run(config.default_path(), self_test="--self-test" in sys.argv))
