# License Server - سرور مدیریت لایسنس

سیستم مدیریت لایسنس برای Network Asset Manager با قابلیت‌های پیشرفته امنیتی و عملکرد بهینه

## ویژگی‌ها

✅ **پلن‌های مختلف:**

- **Pilot**: تست 1 ماهه (5 asset, 2 discovery/audit/harden/monitor)
- **Basic1**: شبکه کوچک (15 دستگاه، 1 سال)
- **Basic2**: شبکه متوسط (50 دستگاه، 1 سال)
- **Basic3**: شبکه بزرگ (150 دستگاه، 1 سال)
- **Enterprise**: نامحدود (1 سال)

✅ **امنیت:**

- توکن منحصر به فرد برای هر سازمان
- VM Fingerprinting (قفل روی یک ماشین)
- چک روزانه heartbeat
- تبدیل خودکار به Pilot بعد از 48 ساعت قطع ارتباط
- احراز هویت JWT برای ادمین
- امضای درخواست با HMAC-SHA256
- ذخیره‌سازی رمزنگاری شده در کلاینت
- Rate limiting با Redis
- Logging ساختاریافته

✅ **محدودیت‌های عملیاتی:**

- تعداد Asset
- تعداد Discovery
- تعداد Audit
- تعداد Harden
- تعداد Monitor (NOC/SOC)

✅ **عملکرد:**

- Connection pooling برای دیتابیس
- ایندکس‌های بهینه شده
- Middleware برای مانیتورینگ

## نصب

### نصب سریع

```bash
cd license_server
pip install -r requirements.txt

# راه‌اندازی PostgreSQL و Redis
createdb license_db
sudo systemctl start redis-server

# تنظیمات
cp .env.example .env
nano .env

# اجرای migrations
alembic upgrade head

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### Public (Client)
- `POST /api/licenses/activate` - فعال‌سازی
- `POST /api/licenses/validate` - اعتبارسنجی
- `POST /api/licenses/heartbeat` - چک روزانه
- `POST /api/licenses/consume` - مصرف عملیات

### Admin
- `POST /api/admin/login` - ورود و دریافت JWT token
- `POST /api/admin/licenses` - ساخت لایسنس
- `GET /api/admin/licenses` - لیست
- `GET /api/admin/licenses/{key}` - جزئیات
- `DELETE /api/admin/licenses/{key}` - غیرفعال

## مثال استفاده

### ورود ادمین

```bash
curl -X POST "http://localhost:8000/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "change-this-password"}'
```

### ساخت لایسنس (Admin)

```bash
TOKEN="your-jwt-token-here"

curl -X POST "http://localhost:8000/api/admin/licenses" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
"customer_name": "شرکت نمونه",
"customer_email": "info@example.com",
"organization_name": "شرکت فناوری نمونه",
"plan_type": "basic2"
  }'
```

### فعال‌سازی (Client)

```bash
curl -X POST "http://localhost:8000/api/licenses/activate" \
  -H "Content-Type: application/json" \
  -d '{
"license_key": "XXXX-XXXX-XXXX-XXXX",
"vm_fingerprint": "unique-vm-id-here"
  }'
```

### Heartbeat روزانه (Client)

```bash
curl -X POST "http://localhost:8000/api/licenses/heartbeat" \
  -H "Content-Type: application/json" \
  -d '{
"license_key": "XXXX-XXXX-XXXX-XXXX",
"organization_token": "org-token-from-activation",
"vm_fingerprint": "unique-vm-id-here"
  }'
```

### مصرف عملیات (Client)

```bash
curl -X POST "http://localhost:8000/api/licenses/consume" \
  -H "Content-Type: application/json" \
  -d '{
"license_key": "XXXX-XXXX-XXXX-XXXX",
"organization_token": "org-token",
"vm_fingerprint": "vm-id",
"operation_type": "discovery",
"count": 1
  }'
```

## Client SDK

یک کتابخانه کلاینت کامل Python ارائه شده است:

```python
from client import LicenseClient, HeartbeatService

# ایجاد کلاینت
client = LicenseClient(server_url="http://localhost:8000")

# فعال‌سازی
result = client.activate("XXXX-XXXX-XXXX-XXXX")
print(f"Activated: {result['plan_type']}")

# اعتبارسنجی
result = client.validate()
if result['valid']:
    print(f"Valid - Limits: {result['limits']}")

# مصرف عملیات
result = client.consume(operation_type="discovery", count=1)

# شروع heartbeat خودکار
heartbeat = HeartbeatService(client, interval_seconds=3600)
heartbeat.start()
```

مستندات کامل در [client/README.md](client/README.md)

## معماری امنیتی

- **JWT Authentication**: احراز هویت ادمین با توکن‌های JWT
- **Request Signing**: امضای درخواست‌های حساس با HMAC-SHA256
- **VM Fingerprinting**: قفل لایسنس روی سخت‌افزار
- **Encrypted Storage**: ذخیره‌سازی رمزنگاری شده با Fernet
- **Rate Limiting**: محدودیت درخواست با Redis

## مستندات

- [راهنمای نصب کامل](SETUP.md)
- [مستندات Client SDK](client/README.md)
