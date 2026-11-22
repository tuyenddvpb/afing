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
| `sudo python -m afing dhcp` | Chỉ nghe và in từng gói DHCP (để thử, xem mục "Nghe DHCP") |
| `python -m afing mdns` | In mọi thứ nghe được qua mDNS trong 12 giây (để thử) |
| `python -m afing update-oui` | Tải bảng hãng sản xuất (OUI) mới nhất từ IEEE |

## Dashboard

- **Bảng thiết bị**: alias, loại, tên, IP, MAC, hãng/model, thời gian. Lọc theo Online, Offline,
  Unknown (thiết bị lạ); tìm theo mọi trường. Trên điện thoại bảng chuyển thành dạng thẻ.
- **Bấm vào một thiết bị** để mở trang chi tiết:
  - sửa tên, **loại** (khi afing đoán sai hoặc để trống), **của ai**, ghi chú;
  - đánh dấu **thiết bị quen**, và chọn cách báo riêng cho máy đó (luôn báo / không bao giờ báo);
  - xem mọi thông tin afing biết (kể cả thông tin DHCP), **dải thời gian có mặt 14 ngày** và lịch sử;
  - **gộp** vào thiết bị khác: dùng khi một máy đổi MAC và hiện thành dòng mới - dòng mới nhận
    alias, tên, lịch sử của dòng cũ;
  - **xoá** thiết bị cùng lịch sử.
- **Thiết bị lạ**: thiết bị chưa được đánh dấu quen có nhãn "unknown"; nút "Mark all as known"
  đánh dấu hết một lượt sau khi bạn đã rà danh sách.
- **Ai đang ở nhà**: điền "Belongs to" cho điện thoại của từng người, dashboard hiện ai đang có mặt.
- **Thanh trên cùng**: tạm tắt thông báo 1/8/24 giờ, xuất danh sách thiết bị và lịch sử ra CSV
  (mở được bằng Excel), **Settings** (sửa `afing.cfg`, gửi tin thử, xem log), chọn ngôn ngữ
  English / Tiếng Việt.

Trang Settings và log chỉ mở được từ chính máy chạy afing, hoặc khi đã đặt mật khẩu.

### Mật khẩu

Nếu để `host = 0.0.0.0` cho máy khác trong mạng xem, hãy đặt `password` trong mục `[web]`. Trình
duyệt sẽ hỏi tên đăng nhập và mật khẩu; tên gõ gì cũng được. Kết nối là HTTP thường (không mã
hoá), nên mật khẩu này chỉ để chặn người trong mạng nhà mở nhầm, không đủ để đưa dashboard ra
Internet.

## Cấu hình: file `afing.cfg`

Mọi thiết lập nằm trong file `afing.cfg`, sửa bằng Notepad. File được tự tạo với giá trị mặc định
ở lần chạy đầu, nằm cạnh `afing.exe` (bản đóng gói) hoặc ở thư mục bạn đang đứng (chạy từ mã
nguồn). Mỗi dòng đều có chú thích; các mục chính:

```ini
[web]
port = 8080            ; cổng của dashboard
host = 127.0.0.1       ; 0.0.0.0 = cho máy khác trong LAN xem
open_browser = yes     ; tự mở trình duyệt khi bấm đúp afing.exe

[scan]
subnet =               ; để trống = tự dò
interval = 10
offline_after = 45
dhcp = yes

[data]
database =             ; để trống = afing.db cạnh file này
log_file =

[notify]               ; điền bằng lệnh notify-setup
telegram_token =
leave_after_minutes = 5
```

(Trong file thật, chú thích nằm ở dòng riêng bắt đầu bằng `#`; đừng viết chú thích cùng dòng với
giá trị.)

- Sửa xong thì khởi động lại afing. Với bản tự chạy nền: chạy lại `afing.exe install-autostart`
  (quyền admin) hoặc khởi động lại máy. Riêng mục `[notify]` được áp dụng ngay.
- Tham số dòng lệnh, nếu có, được ưu tiên hơn file cấu hình. Dùng file khác bằng `--config`.
- Giá trị sai (ví dụ `port = abc`) sẽ được báo rõ dòng nào khi khởi động.
- File chứa token thông báo, đừng chia sẻ nó.

Tham số dòng lệnh tương ứng (xem đủ bằng `python -m afing --help`):

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
| `--no-dhcp` | | Không nghe gói DHCP |

Dashboard không có đăng nhập. Mặc định chỉ máy đang chạy afing mở được; với `--host 0.0.0.0`
thì mọi máy trong LAN đều xem và đổi tên thiết bị được. Đừng mở cổng này ra Internet.

## Cài đặt trên Windows

Cách dễ nhất là dùng bộ cài **`afing-setup.exe`** (tự build bằng `build_exe.bat`, xem mục dưới):

- cài vào `C:\Program Files\afing`, đăng ký tự chạy khi Windows khởi động và chạy ngay;
- thêm biểu tượng afing ở **khay hệ thống** (cạnh đồng hồ): rê chuột để xem số thiết bị online,
  bấm để mở dashboard;
- gỡ bằng "Add or remove programs"; cấu hình và dữ liệu được giữ lại.

Khi cài bằng bộ cài, cấu hình và database nằm trong thư mục cài đặt, nên hãy sửa thiết lập qua
**Settings trên dashboard** (hoặc mở Notepad bằng quyền admin).

**Cập nhật**: mỗi ngày afing hỏi GitHub một lần xem có bản mới và báo trên dashboard (tắt bằng
`update_check = no`). Cài bản mới bằng `afing.exe update` trong Command Prompt quyền admin: lệnh
này chỉ tải từ kho mã của afing và chỉ cài khi file khớp mã SHA-256 của bản phát hành.

Phát hành bản mới (dành cho người giữ kho mã): đẩy một tag dạng `v1.2.0`; workflow sẽ build, thử
và tạo bản phát hành kèm `afing-setup.exe`, `afing.exe`, `afing-tray.exe` và mã SHA-256.

## Đóng gói thành file .exe (Windows)

Gói thành một file `afing.exe` duy nhất, chạy được trên máy Windows khác mà không cần cài Python.
File exe phải được build trên Windows. Có hai cách:

- **Trên máy bạn:** bấm đúp `build_exe.bat` (cần Python 3.9+). Script cài PyInstaller, chạy test,
  rồi tạo trong thư mục `dist`: `afing.exe`, `afing-tray.exe` (biểu tượng khay hệ thống), và
  `afing-setup.exe` nếu máy có [Inno Setup 6](https://jrsoftware.org/isdl.php).
  Kèm theo là `dist\setup.bat` để khỏi gõ lệnh khi nâng cấp: chép nó một lần vào thư mục afing
  (cạnh `afing.exe`) rồi bấm đúp. Nó tự xin quyền admin, chạy `uninstall-autostart`, dừng lại chờ
  bạn tự chép file exe mới vào, rồi chạy `install-autostart`. Nó không chép hay xoá file nào.
- **Để GitHub build:** workflow "Build Windows exe" chạy khi đẩy một tag dạng `v1.0` (hoặc bấm Run
  workflow trong tab Actions) và tạo bản phát hành kèm các file trên.

Dùng trên máy đích:

- Bấm đúp `afing.exe`: tự quét liên tục và mở dashboard trong trình duyệt. Nếu afing đã chạy nền
  thì chỉ mở dashboard của bản đang chạy.
- `afing-tray.exe` (đặt cạnh `afing.exe`) là biểu tượng khay hệ thống; `install-autostart` tự bật nó.
- Muốn nghe DHCP (lấy tên iPhone...): bấm chuột phải > "Run as administrator".
- Cấu hình (`afing.cfg`) và dữ liệu (`afing.db`, `oui.csv`) nằm cạnh file exe; chép cả thư mục nếu muốn mang theo lịch sử
  và alias.
- Các lệnh khác vẫn dùng được từ terminal: `afing.exe scan`, `afing.exe mdns`,
  `afing.exe --host 0.0.0.0`...

### Tự chạy khi Windows khởi động

Mở Command Prompt bằng "Run as administrator" tại thư mục chứa `afing.exe` rồi chạy:

```
afing.exe install-autostart
```

Lệnh này tạo một tác vụ tên `afing` trong Task Scheduler và chạy nó ngay. Từ đó afing tự chạy
nền mỗi khi máy bật hoặc khởi động lại, không cần ai đăng nhập, không hiện cửa sổ, có sẵn quyền
admin (nghe được DHCP), tự chờ tới khi có mạng và tự chạy lại nếu bị lỗi. Dashboard vẫn ở
http://localhost:8080; log ghi vào `afing.log` cạnh file exe.

- Bản chạy nền dùng đúng file `afing.cfg` cạnh file exe. Đổi cổng web hay thiết lập khác: sửa
  `afing.cfg` rồi chạy lại `afing.exe install-autostart`.
- Tắt tự chạy: `afing.exe uninstall-autostart` (dữ liệu vẫn giữ nguyên).
- Đừng di chuyển hay đổi tên `afing.exe` sau khi cài; nếu cần thì gỡ, chuyển, rồi cài lại.

Chạy từ mã nguồn thì dùng `python -m afing install-autostart` với cùng ý nghĩa.

File exe không có chữ ký số nên lần đầu Windows SmartScreen sẽ cảnh báo (bấm More info > Run
anyway), và một số phần mềm diệt virus có thể báo nhầm với file gói bằng PyInstaller.

## Cách quét

| Chế độ | Yêu cầu | Đặc điểm |
|---|---|---|
| `passive` | không | Gửi một gói UDP rỗng tới mọi IP để hệ điều hành tự phân giải ARP, rồi đọc bảng ARP. Thiết bị mới xuất hiện sau 1 lượt quét. Thiết bị rời mạng được phát hiện chậm hơn: khoảng một phút trên Linux, có thể vài phút tới vài chục phút trên Windows/macOS do hệ điều hành giữ cache ARP. |
| `arp` | `pip install scapy` + chạy bằng root/sudo (Windows cần thêm Npcap) | ARP scan chủ động, phát hiện rời mạng ngay ở các lượt quét kế tiếp. |

`auto` (mặc định) dùng `arp` nếu đủ điều kiện, không thì dùng `passive`.

Trên **Windows**, chế độ `passive` còn hỏi lại từng địa chỉ trong bảng ARP bằng hàm `SendARP` của
hệ điều hành (không cần quyền admin hay Npcap) và chỉ giữ thiết bị còn trả lời, nên thiết bị rời
mạng được phát hiện trong khoảng một phút thay vì nhiều phút.

## Thông báo ra điện thoại

afing có thể nhắn cho bạn khi có **thiết bị mới**, khi một thiết bị **rời mạng** và khi nó **quay
lại** - kể cả lúc bạn không ở nhà, vì tin đi qua Internet tới app trên điện thoại. Máy chạy afing
chỉ gọi HTTPS ra ngoài; không phải mở cổng nào vào mạng nhà.

```bash
python -m afing notify-setup
```

(bản exe: `afing.exe notify-setup`). Lệnh hỏi bạn chọn kênh rồi gửi một tin thử:

- **Telegram** (khuyên dùng): tạo bot bằng cách nhắn `/newbot` cho @BotFather, dán token, rồi nhắn
  cho bot một chữ để afing biết gửi cho ai.
- **ntfy**: cài app ntfy, đăng ký chủ đề ngẫu nhiên mà afing in ra. Không cần tài khoản.

Không cần khởi động lại afing: bản đang chạy (kể cả bản tự chạy nền) nhận cấu hình mới ở lượt
quét kế tiếp. `notify-test` gửi lại tin thử; `notify-off` tắt và xoá cấu hình.

Chọn báo cái gì (mục `[notify]`, hoặc Settings trên dashboard):

| Thiết lập | Ý nghĩa |
|---|---|
| `new_device_alerts = yes` | Báo khi có thiết bị chưa từng thấy. Tin Telegram kèm hai nút để đánh dấu quen / lạ ngay. |
| `presence_alerts = all` | Báo rời mạng / quay lại cho mọi thiết bị. `unknown` = chỉ thiết bị chưa đánh dấu quen; `none` = không báo. |
| `quiet_hours = 23:00-07:00` | Không báo rời mạng / quay lại trong khoảng này. Thiết bị lạ mới vào vẫn được báo. |

Từng thiết bị có thể đặt riêng trên dashboard: "luôn báo" (ví dụ camera, NAS - báo cả trong giờ
yên lặng) hoặc "không bao giờ báo". Tạm tắt mọi thông báo bằng `/mute 2h` hoặc nút trên dashboard.

Để không bị làm phiền bởi thiết bị chập chờn (điện thoại ngủ, sóng yếu):

- chỉ báo "rời mạng" khi thiết bị vắng mặt liên tục 5 phút (đổi bằng `"leave_after_minutes"`
  trong mục `[notify]` của `afing.cfg`);
- chỉ báo "quay lại" cho thiết bị đã được báo rời mạng;
- lần quét đầu tiên trên database trống gộp thành một tin tóm tắt.

Lưu ý: nội dung thông báo (tên, IP, MAC thiết bị) đi qua máy chủ của Telegram hoặc ntfy. Cấu hình
lưu trong mục `[notify]` của `afing.cfg` và chứa token - đừng chia sẻ file này.

## Báo cáo online/offline

Ngoài tin báo từng sự kiện, afing gửi được **báo cáo tổng hợp** danh sách thiết bị online và
offline (gần giống bảng trên dashboard) qua kênh đã đặt ở mục `[notify]`.

**Định kỳ** - đặt trong mục `[report]` của `afing.cfg`:

```ini
[report]
times = 08:00, 21:00       # gửi vào các giờ cố định mỗi ngày (giờ của máy chạy afing)
interval_minutes = 0       # hoặc lặp lại mỗi N phút, ví dụ 60; 0 = tắt
offline_days = 7           # chỉ liệt kê thiết bị offline thấy trong 7 ngày gần đây; 0 = tất cả
telegram_commands = yes
```

(Chú thích `#` ở trên chỉ để minh hoạ; trong file thật hãy để chú thích ở dòng riêng.) Thay đổi
ở mục này được áp dụng ngay, không cần khởi động lại.

**Theo yêu cầu** - nhắn cho bot Telegram:

| Lệnh | Trả về |
|---|---|
| `/report` | Tất cả thiết bị, online và offline |
| `/online` | Chỉ thiết bị đang online |
| `/offline` | Chỉ thiết bị đang offline |
| `/who` | Ai đang ở nhà (theo trường "Belongs to" của thiết bị) |
| `/find <chữ>` | Tìm thiết bị theo alias, tên, IP, MAC |
| `/rename <alias> = <tên mới>` | Đổi tên thiết bị |
| `/known <alias>` | Đánh dấu thiết bị quen |
| `/mute 2h`, `/unmute` | Tạm tắt / bật lại thông báo (`30m`, `2h`, `1d`) |
| `/help` | Danh sách lệnh |

Bot chỉ trả thông tin thiết bị cho đúng cuộc trò chuyện có `telegram_chat_id` trong file cấu
hình. Người khác nhắn cho bot sẽ không nhận được gì, trừ `/start` hoặc `/chatid` trả về ID cuộc
trò chuyện của chính họ (tiện để lấy chat_id khi tự cấu hình). Lệnh theo yêu cầu chỉ có với
Telegram; ntfy chỉ nhận báo cáo định kỳ.

Lưu ý: afing phải đang chạy thì bot mới trả lời. Lệnh nhắn lúc afing tắt sẽ bị bỏ qua khi nó
chạy lại. Chỉ nên có một bản afing dùng cùng một bot; hai bản cùng lúc sẽ tranh nhau nhận lệnh.

## Nghe DHCP

Khi kết nối vào mạng, thiết bị broadcast gói DHCP chứa tên máy của nó và các dấu hiệu nhận ra
hệ điều hành. afing nghe các gói này (không bao giờ trả lời, nên không ảnh hưởng router) để:

- lấy tên của những thiết bị không quảng bá gì, điển hình là iPhone, iPad, điện thoại Android;
- nhận ra hệ điều hành: iOS/iPadOS, macOS, Windows, Android (kèm số phiên bản), Linux.

Cần quyền mở cổng UDP 67:

```bash
sudo python3 -m afing
```

Trên Windows, chạy terminal bằng "Run as administrator" và cho phép khi tường lửa hỏi. Không đủ
quyền thì afing vẫn chạy bình thường, chỉ bỏ phần này (dòng log "Không nghe DHCP").

Giới hạn:

- Chỉ bắt được gói lúc thiết bị **kết nối (lại)** vào mạng. Thiết bị đang nối sẵn sẽ chưa có
  tên cho tới lần kết nối sau; muốn có ngay thì tắt rồi bật lại Wi-Fi trên thiết bị đó.
- iPhone đang bật "Địa chỉ Wi-Fi bảo mật" (mặc định) **không gửi tên** trong gói DHCP: afing vẫn
  nhận ra là iPhone nhờ vân tay nhưng không có tên riêng. Tắt tuỳ chọn này cho mạng nhà
  (Cài đặt > Wi-Fi > ⓘ cạnh tên mạng) thì iPhone gửi tên đặt trong Cài đặt > Cài đặt chung >
  Giới thiệu > Tên và dùng MAC thật, cố định. Đã kiểm chứng trên một iPhone thật; các bản iOS
  khác có thể khác.
- Khi đổi tuỳ chọn trên, iPhone xuất hiện với MAC mới nên afing coi là thiết bị mới; dòng ứng
  với MAC ngẫu nhiên cũ sẽ nằm lại ở trạng thái ngoại tuyến.
- Không lấy được đời máy (iPhone 13, 15...): gói DHCP không chứa thông tin đó.
- iPhone/iPad/Apple Watch có vân tay DHCP giống nhau; afing coi là iPhone trừ khi tên máy hoặc
  dịch vụ mDNS cho thấy khác.

## Thông tin thu được

- **IP, MAC**: từ ARP.
- **Alias**: mỗi thiết bị được tự gán một bí danh là loài vật trong rừng (🐿️ Squirrel, 🦉 Owl...) để dễ
  nhận ra mà không phải tự đặt tên. Mỗi con vật chỉ thuộc về đúng một thiết bị (database có ràng
  buộc duy nhất): 52 loài rừng được gán trước, hết thì tới 48 loài khác, mỗi loài một emoji
  riêng; chỉ khi có hơn 100 thiết bị mới phải thêm số ("Tiger 2"). Bí danh gắn với địa chỉ MAC và lưu trong database, nên thiết
  bị rời mạng rồi kết nối lại (kể cả với IP khác, kể cả sau khi khởi động lại afing) vẫn giữ đúng
  con vật cũ. Thiết bị đổi MAC (ví dụ iPhone để địa chỉ Wi-Fi bảo mật kiểu "Xoay vòng") sẽ được
  coi là thiết bị mới và nhận con vật khác.
- **Tên và model**, theo thứ tự ưu tiên:
  1. Dịch vụ mDNS/Bonjour mà thiết bị tự quảng bá (Chromecast, Apple TV, iPhone/Mac, Android TV,
     máy in, loa, HomeKit, ESPHome...) - cho tên thân thiện như "TV phòng khách" và model.
  2. UPnP/SSDP `friendlyName`, hãng và model (smart TV, router, console, NAS, loa).
  3. Tên máy thiết bị tự khai trong gói DHCP (xem "Nghe DHCP").
  4. Tên máy: reverse DNS (router), mDNS, NetBIOS (máy Windows).

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

## Ngôn ngữ

`language = en` hoặc `vi` trong mục `[web]` đặt ngôn ngữ cho dashboard, tin nhắn và báo cáo.
Dashboard còn có nút chọn ngôn ngữ riêng cho từng trình duyệt. Dòng lệnh và log luôn là tiếng Việt.

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
