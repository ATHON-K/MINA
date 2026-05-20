# Hướng dẫn chạy đồ án MINA

## Yêu cầu trước khi bắt đầu

| Phần mềm | Phiên bản | Kiểm tra |
|---|---|---|
| Python | **3.11 trở lên** | `python --version` |
| Node.js | **18 trở lên** | `node --version` |

---

## Bước 1 — Lấy DeepSeek API Key

1. Vào **[platform.deepseek.com](https://platform.deepseek.com)** → Đăng ký / Đăng nhập
2. Vào mục **API Keys** → nhấn **Create new key**
3. Sao chép key (dạng `sk-xxxxxxxx...`) — dùng ở Bước 3

---

## Bước 2 — Tạo file `.env`

Mở terminal, chạy lệnh sau trong thư mục `mina_project/backend`:

```powershell
cd mina_project\backend
copy .env.example .env
```

> Script `start.ps1` cũng tự làm bước này nếu chưa có file `.env`.

---

## Bước 3 — Điền API Key vào `.env`

Mở file `mina_project/backend/.env`, tìm dòng:

```
DEEPSEEK_API_KEY=YOUR_DEEPSEEK_API_KEY_HERE
```

Thay bằng key thật:

```
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Lưu file lại.

---

## Bước 4 — Chạy toàn bộ đồ án (tự động — cách khuyến nghị)

Mở PowerShell tại thư mục `mina_project`, chạy:

```powershell
cd mina_project
.\start.ps1
```

Script tự động:
- Tìm Python 3.11+ và Node.js 18+ trên máy
- Tạo virtual environment `backend\.venv` (nếu chưa có)
- Cài Python packages (`pip install -r requirements.txt`)
- Cài Node packages (`npm install`)
- Kiểm tra port trống, tự chuyển port nếu đang bận
- Khởi động Backend trong cửa sổ PowerShell riêng
- Chờ backend sẵn sàng rồi mới khởi động Frontend
- Mở trình duyệt tự động tại `http://localhost:3000`

> Sau khi script chạy xong → bỏ qua Bước 5 & 6.

### Tuỳ chọn nâng cao

```powershell
# Chỉ chạy backend
.\start.ps1 -Mode backend-only

# Chỉ chạy frontend
.\start.ps1 -Mode frontend-only

# Chỉ chạy tests
.\start.ps1 -Mode test-only

# Bỏ qua bước cài packages (đã cài rồi)
.\start.ps1 -NoInstall

# Tạo lại venv từ đầu
.\start.ps1 -Bootstrap

# Chỉ định port cụ thể
.\start.ps1 -BackendPort 8001 -FrontendPort 3001
```

### Tuỳ chỉnh đường dẫn Python/Node (máy đặc biệt)

Đường dẫn Python và cổng mặc định đã được đặt sẵn trong `start.ps1`:

```powershell
$MINA_PYTHON        = "C:\Program Files\Python312\python.exe"
$MINA_BACKEND_PORT  = 8000
$MINA_FRONTEND_PORT = 3000
```

Nếu máy bạn cài Python ở chỗ khác, **chỉnh 3 dòng này** trong `start.ps1` cho đúng đường dẫn, hoặc tạo file `mina_project/toolchain.local.ps1` (ưu tiên cao hơn, không cần sửa `start.ps1`):

```powershell
# toolchain.local.ps1  — không commit file này lên git
$MINA_PYTHON = "C:\Users\TenBan\AppData\Local\Programs\Python\Python311\python.exe"
$MINA_NODE   = "C:\Program Files\nodejs\node.exe"
$MINA_BACKEND_PORT  = 8000
$MINA_FRONTEND_PORT = 3000
```

Tìm đường dẫn Python đang dùng trên máy:

```powershell
where.exe python
# hoặc
(Get-Command python).Source
```

---

## Bước 5 — Chạy Backend (thủ công — nếu không dùng start.ps1)

Mở **terminal thứ nhất**:

```powershell
cd mina_project\backend

# Tạo môi trường ảo (chỉ 1 lần)
python -m venv .venv

# Kích hoạt
.venv\Scripts\Activate.ps1

# Cài thư viện (chỉ 1 lần)
pip install -r requirements.txt

# Chạy server
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Backend sẵn sàng khi thấy:
```
INFO:     Application startup complete.
```

**Giữ terminal này mở.**

---

## Bước 6 — Chạy Frontend (thủ công — nếu không dùng start.ps1)

Mở **terminal thứ hai**:

```powershell
cd mina_project\frontend

# Cài packages (chỉ 1 lần)
npm install

# Chạy dev server
npm run dev
```

Frontend sẵn sàng khi thấy:
```
  ➜  Local:   http://localhost:3000/
```

---

## Bước 7 — Mở giao diện

Truy cập trình duyệt:

```
http://localhost:3000
```

---

## Bước 8 — Thực hiện scan

1. **Nhập domain mục tiêu** vào ô TARGET LOCK (ví dụ: `example.com`)
2. **Chọn profile** scan: Quick / Balanced / Deep
3. **Bật/tắt agents** theo nhu cầu ở phần AGENT DISPATCH
4. **Nhấn `[ INITIATE RECON ]`** để bắt đầu
5. Theo dõi tiến trình trên panel Lead Queue và Metrics Dashboard
6. Khi scan hoàn thành (STATUS: COMPLETE), nhấn **EXPORT** để tải báo cáo

---

## Chạy Tests

```powershell
# Qua start.ps1
.\start.ps1 -Mode test-only

# Hoặc thủ công
cd mina_project\backend
.venv\Scripts\Activate.ps1
python -m pytest tests/ -v

# Chỉ unit tests
python -m pytest tests/unit/ -v -m unit

# Chỉ integration tests
python -m pytest tests/integration/ -v -m integration
```

---

## Khắc phục sự cố thường gặp

| Lỗi | Nguyên nhân | Cách sửa |
|---|---|---|
| `Python 3.11+ not found` | Python chưa cài hoặc sai phiên bản | Cài Python 3.11+ từ python.org, tích chọn "Add to PATH" |
| `Node.js 18+ not found` | Node chưa cài hoặc sai phiên bản | Cài Node 18+ từ nodejs.org |
| `Port XXXX is in use` | Cổng đã bị dùng | Script tự chuyển port, hoặc dùng `-BackendPort 8001` |
| `.env still has placeholder` | Chưa điền API key | Mở `backend/.env`, thay `YOUR_DEEPSEEK_API_KEY_HERE` |
| Backend không start | Thiếu thư viện | Chạy `.\start.ps1 -Bootstrap` |
| Frontend trắng, không có dữ liệu | Backend chưa chạy | Đảm bảo backend chạy trước ở port 8000 |

---

## Lưu ý quan trọng

- Chỉ scan những domain bạn được **phép kiểm tra**
- Lần đầu cài packages mất khoảng **3–5 phút**
- Nếu PowerShell báo lỗi policy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- Report được lưu tại `backend/output/sessions/<session_id>/`
