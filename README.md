# afing

Quét và theo dõi các thiết bị đang kết nối vào mạng LAN/Wi-Fi, lưu vào SQLite và hiển thị
trên một web dashboard cập nhật gần thời gian thực. Chạy trên một máy tính nằm trong mạng cần quét.

- Chỉ cần **Python 3.9+**, không phải cài thư viện nào.
- Chạy được trên Linux, macOS, Windows.

## Chạy

```bash
python -m afing
```

Mở http://localhost:8080. Mặc định afing tự dò subnet của máy, quét mỗi 10 giây.

| Lệnh | Tác dụng |
|---|---|
| `python -m afing` | Quét liên tục, ghi DB, mở web dashboard |
| `python -m afing scan` | Quét một lần, in bảng ra màn hình |
| `python -m afing update-oui` | Tải bảng hãng sản xuất (OUI) mới nhất từ IEEE |

Tuỳ chọn thường dùng (xem đủ bằng `python -m afing --help`):

| Tuỳ chọn | Mặc định | Ý nghĩa |
|---|---|---|
| `--subnet 192.168.1.0/24` | tự dò | Subnet cần quét |
| `--interval 10` | 10 | Số giây giữa hai lượt quét |
| `--offline-after 45` | 45 | Không thấy quá số giây này thì coi là đã rời mạng |
| `--host 0.0.0.0` | 127.0.0.1 | Cho máy khác trong LAN mở dashboard |
| `--port 8080` | 8080 | Cổng web |
| `--db afing.db` | afing.db | File SQLite |
| `--method arp` | auto | Cách quét (xem dưới) |
| `--no-web` | | Chỉ quét và ghi DB |

Dashboard không có đăng nhập. Mặc định chỉ máy đang chạy afing mở được; với `--host 0.0.0.0`
thì mọi máy trong LAN đều xem và đổi tên thiết bị được. Đừng mở cổng này ra Internet.

## Cách quét

| Chế độ | Yêu cầu | Đặc điểm |
|---|---|---|
| `passive` | không | Gửi một gói UDP rỗng tới mọi IP để hệ điều hành tự phân giải ARP, rồi đọc bảng ARP. Thiết bị mới xuất hiện sau 1 lượt quét. Thiết bị rời mạng được phát hiện chậm hơn: khoảng một phút trên Linux, có thể vài phút tới vài chục phút trên Windows/macOS do hệ điều hành giữ cache ARP. |
| `arp` | `pip install scapy` + chạy bằng root/sudo (Windows cần thêm Npcap) | ARP scan chủ động, phát hiện rời mạng ngay ở các lượt quét kế tiếp. |

`auto` (mặc định) dùng `arp` nếu đủ điều kiện, không thì dùng `passive`.

## Thông tin thu được

- **IP, MAC**: từ ARP.
- **Tên và model**, theo thứ tự ưu tiên:
  1. Dịch vụ mDNS/Bonjour mà thiết bị tự quảng bá (Chromecast, Apple TV, iPhone/Mac, Android TV,
     máy in, loa, HomeKit, ESPHome...) - cho tên thân thiện như "TV phòng khách" và model.
  2. UPnP/SSDP `friendlyName`, hãng và model (smart TV, router, console, NAS, loa).
  3. Tên máy: reverse DNS (router), mDNS, NetBIOS (máy Windows).

  Thiết bị không trả lời nguồn nào (thường là điện thoại đang khoá màn hình, thiết bị IoT rẻ)
  thì không có tên; bấm vào tên trên dashboard để tự đặt. Thiết bị chưa có tên được dò lại
  mỗi 5 phút.
- **Loại thiết bị và hệ điều hành**: suy đoán theo luật trong `afing/classify.py` từ dịch vụ
  thiết bị quảng bá, loại UPnP, chữ trong tên/model, hãng sản xuất. Đây là phỏng đoán có căn cứ,
  không phải sự thật; không đủ dấu hiệu thì để trống chứ không đoán bừa.
- **Hãng sản xuất**: tra 3 byte đầu của MAC trong bảng OUI của IEEE. Lần chạy đầu afing tự tải
  bảng này về `oui.csv` cạnh file DB (tắt bằng `--no-oui-download`). Điện thoại/laptop đời mới
  dùng MAC ngẫu nhiên cho từng Wi-Fi nên không tra được hãng.
- **Trạng thái**: trực tuyến/ngoại tuyến, thời điểm thấy lần đầu và gần nhất.
- **Sự kiện**: thiết bị mới, rời mạng, kết nối lại, đổi IP.

## Dữ liệu

SQLite, hai bảng (schema trong `afing/db.py`):

- `devices`: mỗi MAC một dòng, cập nhật sau từng lượt quét.
- `events`: lịch sử sự kiện.

API: `GET /api/state` trả JSON gồm trạng thái quét, danh sách thiết bị và 50 sự kiện gần nhất.

## Test

```bash
python -m unittest discover -s tests
```

Chỉ quét mạng của chính bạn hoặc mạng bạn được phép quản trị.
