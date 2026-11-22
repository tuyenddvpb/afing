"""afing - quét và theo dõi thiết bị trong mạng LAN/Wi-Fi."""

__version__ = "0.1.0"


def _safe_output() -> None:
    """Windows dùng bảng mã cũ khi đầu ra không phải console (ghi ra file, chạy nền): thay ký tự
    không in được bằng "?" thay vì để chương trình văng lỗi UnicodeEncodeError."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


_safe_output()
