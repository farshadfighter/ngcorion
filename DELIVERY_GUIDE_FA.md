# راهنمای کامل تحویل و استقرار پروژه Netease

---

## ۱. معماری کلی سیستم

```
┌─────────────────────────────────────────────┐
│                  VPS / سرور                 │
│                                             │
│  ┌──────────────────┐  ┌─────────────────┐  │
│  │  netease_server  │  │   PostgreSQL 16  │  │
│  │  (باینری اجرایی) │◄─►│   (داخل Docker) │  │
│  │  پورت: 8000      │  │   پورت: 5432    │  │
│  └──────────────────┘  └─────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
              ▲
              │ HTTP
              │
┌─────────────────────────┐
│  فرانت‌اند / مرورگر     │
│  http://IP-VPS:8000     │
└─────────────────────────┘
```

**نکته مهم:** باینری `netease_server` کاملاً مستقل است و نیازی به نصب Python روی سرور ندارد.
تنها پیش‌نیاز سرور: **Docker**

---

## ۲. مراحل کار — نقشه راه

```
[ ماشین توسعه‌دهنده ]          [ VPS / سرور مقصد ]

 ۱. git clone / کد پروژه
 ۲. pip install dependencies
 ۳. bash build.sh
       ↓
 ۴. zip کردن dist
       ↓
 ۵. ─────── انتقال فایل ──────→  ۶. نصب Docker روی VPS
                                  ۷. انتقال و extract فایل‌ها
                                  ۸. تنظیم .env
                                  ۹. راه‌اندازی PostgreSQL
                                 ۱۰. اجرای سرور
                                 ۱۱. تنظیم autostart (اختیاری)
```

---

## ۳. مرحله اول — ساخت باینری روی ماشین توسعه‌دهنده

این مرحله را شما (توسعه‌دهنده) روی کامپیوتر خودتان انجام می‌دهید.

### ۳.۱ پیش‌نیازها روی ماشین توسعه

- Linux (ترجیحاً همان توزیعی که VPS دارد — مثلاً Ubuntu 22.04)
- Python 3.13 یا بالاتر
- venv پروژه آماده و فعال باشد

> ⚠️ باینری ساخته‌شده روی Linux فقط روی Linux اجرا می‌شود.
> اگر می‌خواهید روی Windows یا Mac مستقر کنید، باید بیلد را روی همان سیستم‌عامل انجام دهید.

### ۳.۲ آماده‌سازی محیط

```bash
cd /home/zi/Desktop/main_app/netease

# فعال‌سازی محیط مجازی
source venv/bin/activate

# نصب تمام وابستگی‌ها (از جمله nuitka)
pip install -r requirements.txt

# بررسی نصب بودن nuitka
python -m nuitka --version
```

### ۳.۳ اجرای بیلد

```bash
bash build.sh
```

**این فرآیند ۵ تا ۱۵ دقیقه طول می‌کشد.** در طول بیلد:
- Nuitka کد Python را به C کامپایل می‌کند
- تمام کتابخانه‌ها درون باینری بسته می‌شوند
- فایل‌های JSON و قالب‌های SSH کپی می‌شوند

پس از اتمام، این ساختار ایجاد می‌شود:

```
dist_build/
└── netease_server.dist/
    ├── netease_server          ← فایل اجرایی اصلی
    ├── alembic/                ← فایل‌های migration دیتابیس
    ├── alembic.ini             ← تنظیمات alembic
    ├── .env.example            ← نمونه فایل تنظیمات
    ├── psycopg2_binary.libs/   ← کتابخانه‌های C مورد نیاز
    └── [کتابخانه‌های دیگر]/   ← .so files
```

### ۳.۴ تست سریع قبل از تحویل

قبل از ارسال به سرور، یک بار روی ماشین خودتان تست کنید:

```bash
# مطمئن شوید PostgreSQL در دسترس است
docker compose up -d

# رفتن به پوشه dist
cd dist_build/netease_server.dist

# کپی و ویرایش تنظیمات
cp .env.example .env
# .env را باز کنید و SECRET_KEY را تغییر دهید

# اجرای سرور
./netease_server
```

در مرورگر باز کنید: `http://localhost:8000/docs` — اگر صفحه Swagger باز شد، بیلد موفق است.

### ۳.۵ آماده‌سازی پکیج برای ارسال

```bash
# از پوشه پروژه
cd /home/zi/Desktop/main_app/netease/dist_build

# zip کردن محتویات
zip -r netease_server_v1.0.zip netease_server.dist/

# همچنین docker-compose.yml را از ریشه پروژه کپی کنید
cp ../docker-compose.yml netease_server_v1.0_docker.yml
```

**فایل‌هایی که باید به سرور بفرستید:**
```
netease_server_v1.0.zip          ← باینری و فایل‌های جانبی
netease_server_v1.0_docker.yml  ← برای راه‌اندازی PostgreSQL
```

---

## ۴. مرحله دوم — آماده‌سازی VPS (سرور خالی)

این مرحله را روی سرور مقصد انجام می‌دهید که **هیچ چیزی روی آن نصب نیست**.

### ۴.۱ اتصال به VPS

```bash
ssh root@IP-VPS
# یا با کاربر sudo:
ssh username@IP-VPS
```

### ۴.۲ به‌روزرسانی سیستم

```bash
# Ubuntu / Debian
apt update && apt upgrade -y

# CentOS / RHEL / Rocky Linux
dnf update -y
```

### ۴.۳ نصب Docker

Docker هم موتور اجرا و هم ابزار docker compose را به همراه دارد.

**روی Ubuntu / Debian:**
```bash
# نصب پیش‌نیازها
apt install -y ca-certificates curl gnupg

# اضافه کردن کلید GPG رسمی Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# اضافه کردن repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | tee /etc/apt/sources.list.d/docker.list > /dev/null

# نصب Docker
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# بررسی نصب
docker --version
docker compose version
```

**روی CentOS / Rocky Linux:**
```bash
dnf install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl start docker
systemctl enable docker

docker --version
docker compose version
```

### ۴.۴ فعال‌سازی خودکار Docker هنگام روشن شدن سرور

```bash
systemctl enable docker
systemctl start docker
```

---

## ۵. مرحله سوم — انتقال فایل‌ها به VPS

### روش ۱: با استفاده از scp (از ماشین توسعه)

```bash
# از ماشین خودتان اجرا کنید (نه سرور)
scp netease_server_v1.0.zip root@IP-VPS:/opt/
scp netease_server_v1.0_docker.yml root@IP-VPS:/opt/docker-compose.yml
```

### روش ۲: با استفاده از wget (روی سرور)

اگر فایل را روی یک فضای ذخیره‌سازی آنلاین (مثل Google Drive یا Dropbox) گذاشتید:

```bash
# روی سرور
wget -O /opt/netease_server_v1.0.zip "LINK_DIRECT_DOWNLOAD"
```

---

## ۶. مرحله چهارم — نصب و راه‌اندازی روی VPS

### ۶.۱ ساختار پوشه‌ها

```bash
# ایجاد پوشه اصلی برنامه
mkdir -p /opt/netease
cd /opt/netease

# کپی فایل docker-compose
cp /opt/docker-compose.yml /opt/netease/docker-compose.yml

# extract باینری
unzip /opt/netease_server_v1.0.zip -d /opt/netease/
# نتیجه: /opt/netease/netease_server.dist/
```

### ۶.۲ تنظیم فایل پیکربندی (.env)

```bash
cd /opt/netease/netease_server.dist

# کپی نمونه تنظیمات
cp .env.example .env

# ویرایش فایل تنظیمات
nano .env
```

محتوای `.env` را به این شکل تنظیم کنید:

```env
# آدرس اتصال به PostgreSQL
# چون PostgreSQL داخل Docker روی همان سرور است، localhost صحیح است
DATABASE_URL=postgresql://netease:1234@localhost/netease_db

# کلید رمزنگاری JWT — این را حتماً تغییر دهید!
# برای تولید کلید تصادفی امن:
# python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=یک-رشته-تصادفی-۶۴-کاراکتری-اینجا-بگذارید

# آدرس و پورت سرور
HOST=0.0.0.0
PORT=8000
```

**تولید SECRET_KEY امن:**
```bash
# اگر Python روی VPS نیست، از این روش استفاده کنید:
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
```

### ۶.۳ راه‌اندازی PostgreSQL با Docker

```bash
cd /opt/netease

# دانلود image و راه‌اندازی PostgreSQL
docker compose up -d

# بررسی اینکه PostgreSQL در حال اجراست
docker compose ps
# باید وضعیت "running" نشان دهد

# بررسی لاگ (اختیاری)
docker compose logs postgres
```

```bash
# تست اتصال به PostgreSQL (اختیاری)
docker exec -it netease-postgres-1 psql -U netease -d netease_db -c "\l"
# باید دیتابیس netease_db را نشان دهد
```

### ۶.۴ دادن مجوز اجرا به باینری

```bash
chmod +x /opt/netease/netease_server.dist/netease_server
```

### ۶.۵ اجرای اولیه سرور (تست دستی)

```bash
cd /opt/netease/netease_server.dist
./netease_server
```

در اولین اجرا، Alembic به طور خودکار تمام جداول دیتابیس را می‌سازد.
خروجی باید چیزی شبیه این باشد:

```
INFO:     Started server process [1234]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**تست از ماشین محلی:**
```bash
curl http://IP-VPS:8000/health
# پاسخ: {"status":"ok","version":"..."}
```

با `Ctrl+C` سرور را متوقف کنید و به مرحله بعد بروید.

---

## ۷. مرحله پنجم — تنظیم autostart با systemd

برای اینکه سرور پس از ریستارت VPS به طور خودکار راه‌اندازی شود:

### ۷.۱ ایجاد فایل service

```bash
nano /etc/systemd/system/netease.service
```

محتوا:
```ini
[Unit]
Description=Netease Backend Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netease/netease_server.dist
ExecStartPre=/bin/bash -c 'cd /opt/netease && docker compose up -d'
ExecStartPre=/bin/sleep 5
ExecStart=/opt/netease/netease_server.dist/netease_server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### ۷.۲ فعال‌سازی و اجرا

```bash
# بارگذاری تنظیمات جدید
systemctl daemon-reload

# فعال‌سازی autostart
systemctl enable netease

# شروع سرویس
systemctl start netease

# بررسی وضعیت
systemctl status netease
```

### ۷.۳ مشاهده لاگ‌های سرور

```bash
# لاگ‌های realtime
journalctl -u netease -f

# لاگ‌های ۱۰۰ خط آخر
journalctl -u netease -n 100
```

---

## ۸. مرحله ششم — تنظیمات فایروال (اختیاری اما توصیه می‌شود)

```bash
# نصب و فعال‌سازی UFW (Ubuntu)
apt install -y ufw

# قوانین پایه
ufw allow ssh          # SSH برای مدیریت سرور
ufw allow 8000/tcp     # پورت API بک‌اند

# فعال‌سازی فایروال
ufw enable

# بررسی وضعیت
ufw status
```

> 💡 اگر می‌خواهید API فقط از طریق دامنه و HTTPS در دسترس باشد (توصیه می‌شود برای production)، به یک reverse proxy مثل Nginx نیاز دارید. اما برای محیط توسعه و تست، همین تنظیمات کافی است.

---

## ۹. تحویل به فرانت‌اند دولوپر (محیط محلی)

اگر فرانت‌اند دولوپر می‌خواهد بک‌اند را **روی لپ‌تاپ خودش** اجرا کند (نه VPS):

### پیش‌نیاز: فقط Docker Desktop

از آدرس `https://www.docker.com/products/docker-desktop/` دانلود و نصب کند.

### فایل‌هایی که به فرانت‌اند دولوپر می‌دهید:

```
📦 پکیج فرانت‌اند
├── netease_server_v1.0.zip     ← باینری و فایل‌های جانبی
└── docker-compose.yml          ← برای PostgreSQL
```

### دستورالعمل برای فرانت‌اند دولوپر:

**قدم ۱ — نصب Docker Desktop** (اگر نصب نیست)

**قدم ۲ — extract و آماده‌سازی**
```bash
# Linux/Mac:
unzip netease_server_v1.0.zip
cd netease_server.dist
cp .env.example .env
```

**قدم ۳ — راه‌اندازی دیتابیس**
```bash
# از پوشه‌ای که docker-compose.yml در آن است:
docker compose up -d
```

**قدم ۴ — اجرای سرور**
```bash
# Linux/Mac:
chmod +x ./netease_server
./netease_server
```

**قدم ۵ — تست**

مرورگر را باز کنید:
- `http://localhost:8000/docs` ← مستندات API
- `http://localhost:8000/health` ← بررسی سلامت

---

## ۱۰. اطلاعات اتصال پیش‌فرض (برای تست)

| موضوع | مقدار |
|-------|-------|
| آدرس API (VPS) | `http://IP-VPS:8000` |
| آدرس API (محلی) | `http://localhost:8000` |
| مستندات Swagger | آدرس بالا + `/docs` |
| نام کاربری پیش‌فرض | `admin` |
| رمز عبور پیش‌فرض | `123456` |
| دیتابیس (کاربر) | `netease` |
| دیتابیس (رمز) | `1234` |
| دیتابیس (نام) | `netease_db` |
| دیتابیس (پورت) | `5432` |

> ⛔ رمزهای بالا فقط برای **تست و توسعه** هستند.
> قبل از تحویل به کلاینت نهایی، حتماً `SECRET_KEY` را تغییر دهید.

---

## ۱۱. پشتیبان‌گیری از دیتابیس

```bash
# ایجاد backup از دیتابیس
docker exec netease-postgres-1 \
    pg_dump -U netease netease_db > backup_$(date +%Y%m%d).sql

# بازیابی backup
docker exec -i netease-postgres-1 \
    psql -U netease netease_db < backup_20260220.sql
```

---

## ۱۲. عیب‌یابی مشکلات رایج

| مشکل | راه‌حل |
|-------|--------|
| `./netease_server: Permission denied` | `chmod +x ./netease_server` |
| `Connection refused` روی پورت 8000 | فایروال پورت 8000 را باز کنید |
| خطای اتصال دیتابیس | `docker compose ps` — مطمئن شوید postgres در حال اجراست |
| `SECRET_KEY` خطا | فایل `.env` را بررسی کنید، کلید باید set شده باشد |
| سرور بعد از ریستارت بالا نیامد | `systemctl status netease` و `journalctl -u netease -n 50` |
| `psycopg2` خطا | مطمئن شوید پوشه `psycopg2_binary.libs/` کنار باینری وجود دارد |

---

## ۱۳. چک‌لیست نهایی قبل از تحویل

**روی ماشین توسعه:**
- [ ] `bash build.sh` بدون خطا اجرا شد
- [ ] باینری روی ماشین توسعه تست و تأیید شد
- [ ] `SECRET_KEY` برای production تغییر کرده
- [ ] `docker-compose.yml` همراه پکیج است

**روی VPS:**
- [ ] Docker نصب و فعال است (`docker --version`)
- [ ] PostgreSQL با Docker Compose بالا است (`docker compose ps`)
- [ ] فایل `.env` تنظیم شده (به‌خصوص `SECRET_KEY`)
- [ ] `./netease_server` بدون خطا اجرا می‌شود
- [ ] آدرس `/health` پاسخ `{"status":"ok"}` می‌دهد
- [ ] `systemctl enable netease` برای autostart انجام شده
- [ ] فایروال پورت 8000 را باز کرده

**برای فرانت‌اند دولوپر:**
- [ ] پکیج zip شده تحویل داده شد
- [ ] `docker-compose.yml` جداگانه تحویل داده شد
- [ ] این راهنما یا نسخه ساده‌شده آن پیوست است
