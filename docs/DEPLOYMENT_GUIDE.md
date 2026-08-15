# Deployment Guide

## راه‌اندازی با دامنه و HTTPS

این پروژه با دامنه‌ی محلی `ngcorion.local` و روی سرور با IP `172.16.200.90` بالا میاد.
مسیریابی و HTTPS (با گواهی self-signed) به‌طور کامل توسط **Traefik** انجام می‌شه. دیگه از
nginx استفاده نمی‌شه: فرانت (بیلد شده‌ی React از `front/dist`) رو **مستقیماً خودِ بک‌اند
(FastAPI)** سرو می‌کنه (بدون کانتینر جدا). بک‌اند فقط از داخل شبکه‌ی داکر و از طریق Traefik
در دسترسه و هیچ پورتی رو مستقیم به هاست باز نمی‌کنه.

> **چرا بدون nginx؟** فرانت از قبل هم‌مبدأ (same-origin) با بک‌اند کار می‌کنه (baseURL نسبی)،
> و بک‌اند از قبل مالک مسیرهای `/api`، `/auth`، `/docs` و `/static` روی همون دامنه بود.
> پس سرو کردن فایل‌های استاتیک SPA از همون بک‌اند، یک کانتینر (و ایمیج nginx و کانفیگش) رو
> کامل حذف می‌کنه بدون اضافه‌شدن هیچ وابستگی‌ای. منطقش تو `app/main.py` (روت catch-all) هست.

> **چرا `ngcorion.local`؟** دامنه‌ی `ngcorion.com` یک سایت واقعی و بی‌ربط به این پروژه‌ست و
> برای تست محلی نباید استفاده بشه (تداخل ایجاد می‌کرد و در دسترس نبود). `.local` یک TLD
> امن برای تست محلیه که با DNS واقعی تداخل نداره.

آدرس‌دهی:
- `https://ngcorion.local/` → فرانت (React build)، و همه‌ی مسیرهای سمت کلاینت
- `https://ngcorion.local/api/...` و `https://ngcorion.local/auth/...` → API بک‌اند (FastAPI)
- `https://ngcorion.local/docs` → مستندات Swagger بک‌اند

### مراحل روی سرور

1. **اضافه کردن دامنه به hosts** (چون DNS واقعی نداره):
   ```
   echo "172.16.200.90 ngcorion.local" | sudo tee -a /etc/hosts
   ```
   این خط رو روی هر کامپیوتری که می‌خواد به سایت وصل بشه باید اجرا کنی (هم روی خود
   سرور اگه از طریق دامنه تستش می‌کنی، هم روی کلاینت‌ها).

2. **گواهی SSL**: گواهی‌ها تو گیت نیستن (`traefik/certs/*.crt` و `*.key` تو `.gitignore`
   هستن)، پس با `git pull` به سرور نمیان و **باید روی خودِ سرور ساخته بشن**. اول
   گواهی‌های قدیمی `ngcorion.com` (اگه مونده) رو پاک کن، بعد گواهی جدید `ngcorion.local`
   رو بساز (self-signed، معتبر برای دامنه‌ی `ngcorion.local` و IP `172.16.200.90`، اعتبار
   ۱ ساله):
   ```bash
   # اگه پوشه‌ی traefik/certs مالکش root باشه، این دستورها رو با sudo بزن وگرنه
   # openssl خطای «Permission denied» موقع نوشتن فایل می‌ده و گواهی ساخته نمی‌شه.
   sudo rm -f traefik/certs/ngcorion.crt traefik/certs/ngcorion.key
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout traefik/certs/ngcorion.local.key \
     -out traefik/certs/ngcorion.local.crt \
     -subj "/C=IR/ST=Tehran/L=Tehran/O=NGCorion/CN=ngcorion.local" \
     -addext "subjectAltName=IP:172.16.200.90,DNS:ngcorion.local"
   ```
   > اگه `tls.yml` به گواهی‌ای اشاره کنه که رو دیسک نیست، Traefik هیچ گواهی معتبری برای
   > پورت ۴۴۳ نداره و هند‌شیک TLS می‌شکنه (`curl` خطای `SSL_ERROR_SYSCALL` می‌ده).
   > Traefik فقط پوشه‌ی `dynamic/` رو watch می‌کنه نه `certs/` رو، پس بعد از ساختن گواهی
   > جدید روی یه استک در حال اجرا، باید Traefik رو ری‌استارت کنی تا گواهی رو بخونه:
   > `docker compose restart traefik`.

3. **Build فرانت**:
   ```bash
   cd /path/to/project
   cd front && npm install && npm run build && cd ..
   ```
   خروجی می‌ره تو `front/dist/` که به‌صورت read-only داخل کانتینر `backend` مانت می‌شه
   (`./front/dist:/app/front/dist:ro`) و توسط FastAPI سرو می‌شه. بعد از هر تغییر تو کد
   فرانت، این مرحله باید دوباره اجرا بشه — دایرکتوری `dist/` تو gitignore هست و در ری‌است
   تازه ساخته نمی‌شه.
   > اگه build با خطای `EACCES: permission denied, mkdir '.../front/dist/...'` خورد،
   > یعنی `front/dist` از یه اجرای قبلی مالکش root شده. چون این پوشه gitignore هست و هر
   > بار از نو ساخته می‌شه، امن‌ترین کار پاک‌کردنشه و بعد build دوباره (بدون sudo، با
   > همون کاربری که داکر رو اجرا می‌کنه):
   > ```bash
   > sudo rm -rf front/dist && npm run build
   > ```

4. **اجرای داکر**:
   ```bash
   docker compose up -d
   ```

5. **آدرس‌ها**:
   - سایت اصلی: `https://ngcorion.local`
   - مستندات API (Swagger UI): `https://ngcorion.local/docs`
   - API base: `https://ngcorion.local/api/...`

   (مرورگر برای گواهی self-signed هشدار می‌ده — Advanced → Accept / Proceed)

### نکات فنی

- فرانت (`src/config/api.js`) از `baseURL` نسبی (`''`) استفاده می‌کنه و مسیرهای
  `/api/...` و `/auth/...` رو خودش کامل می‌سازه؛ یعنی همیشه هم‌مبدأ (same-origin) با
  دامنه‌ای که سایت روش سرو می‌شه صحبت می‌کنه. نیازی به ست کردن یک API URL مطلق تو کد
  یا build نیست.
- سرو شدن SPA تو `app/main.py` تعریف شده: مسیر `/assets` (فایل‌های هش‌دار build) مانت
  می‌شه و یک روت catch-all در انتهای فایل، فایل درخواستی رو از `front/dist` برمی‌گردونه
  و اگه فایل نبود `index.html` رو می‌ده تا React Router بتونه deep-link و refresh رو
  (مثل `/audit/sessions/42`) resolve کنه. این روت **بعد از** همه‌ی روترهای API ثبت شده،
  پس هیچ‌وقت روی `/api`، `/auth`، `/docs`، `/static` سایه نمی‌ندازه.
- مسیریابی همه‌ی مسیرها روی دامنه‌ی `ngcorion.local` به بک‌اند، کاملاً روی Traefik
  تعریف شده (`docker-compose.yml`, لیبل‌های سرویس `backend`). یک روتر واحد کل ترافیک این
  دامنه رو به بک‌اند می‌ده.
- درخواست HTTP ساده به `ngcorion.local` (پورت ۸۰) خودکار ریدایرکت می‌شه به HTTPS.
- بک‌اند هیچ پورتی رو مستقیم به هاست باز نمی‌کنه (`expose: ["8000"]`)؛ فقط از داخل
  شبکه‌ی داکر (توسط Traefik) در دسترسه.
- تنظیمات دیگه‌ی سرویس‌ها (`license-server`, `license-admin`, دیتابیس‌ها) و مسیریابی
  dev قبلی (`license.netease.localhost` روی Traefik، پورت ۸۰) دست‌نخورده باقی مونده و
  تحت تأثیر این تغییرات نیستن.

### پیش‌نیازهای System Configuration

ماژول System Configuration (`/api/system` — تنظیمات زمان، SNMP، Syslog، SMS، SMTP و
گواهی TLS) روی **خودِ هاست** فایل کانفیگ می‌نویسه و سرویس‌ها رو ری‌استارت می‌کنه. قبل از
`docker compose up` این کارها رو روی سرور انجام بده:

1. **ساختن پوشه‌ها و نصب سرویس‌ها روی هاست**:
   ```bash
   sudo mkdir -p /etc/ngcorion/certs
   sudo apt-get install -y snmpd rsyslog
   ```
   > پوشه‌ی `/etc/ngcorion/certs` جاییه که گواهی آپلودشده از UI ذخیره می‌شه
   > (`server.crt` و `server.key`).

2. **فایل `timesyncd.conf` باید از قبل روی هاست وجود داشته باشه**:
   ```bash
   sudo touch /etc/systemd/timesyncd.conf
   ```
   چون این مورد یک bind mount **تک‌فایلی**ه؛ اگه مسیر روی هاست نباشه، داکر به‌جاش یک
   **پوشه** می‌سازه و نوشتن تنظیمات NTP با خطا شکست می‌خوره.

3. **کانتینر بک‌اند رو با کانفیگ جدید بالا بیار** (compose جدید شامل `user: root`،
   `cap_add: [SYS_TIME, NET_ADMIN]` و مانت‌های `/etc/snmp`، `/etc/rsyslog.d`،
   `/etc/systemd/timesyncd.conf`، `/etc/ngcorion`، `/usr/bin/timedatectl` و
   `/run/systemd` هست):
   ```bash
   docker compose up -d backend
   ```

#### محدودیت‌های شناخته‌شده (مهم)

ایمیج بک‌اند روی `python:3.13-slim` ساخته شده و **نه `systemctl` داره نه کتابخانه‌های
systemd**. یعنی با کانفیگ فعلی:

- **نوشتن فایل‌های کانفیگ کار می‌کنه** (`/etc/snmp/snmpd.conf`،
  `/etc/rsyslog.d/99-ngcorion.conf`، `/etc/systemd/timesyncd.conf`) و تنظیمات هم در
  دیتابیس ذخیره می‌شن.
- **مرحله‌ی apply (ری‌استارت سرویس‌ها و `timedatectl`) از داخل کانتینر شکست می‌خوره** و
  API با خطای ۵۰۰ و پیام «تنظیمات ذخیره شد ولی اعمال نشد: Command not found: systemctl»
  برمی‌گرده. مانت‌کردن فقط باینری `timedatectl` کافی نیست: این باینری به
  `/usr/lib/systemd/libsystemd-shared-*.so` لینک شده و از طریق سوکت D-Bus با systemd
  حرف می‌زنه.

  برای این‌که واقعاً کار کنه یکی از این دو راه:
  1. **کلاینت systemd رو داخل ایمیج نصب کن** (`apt-get install -y systemd dbus` تو
     `Dockerfile.netease`) و سوکت D-Bus هاست رو هم مانت کن:
     `- /run/dbus/system_bus_socket:/run/dbus/system_bus_socket`
  2. یا بعد از هر تغییر، سرویس‌ها رو **روی هاست** ری‌استارت کن:
     `sudo systemctl restart snmpd rsyslog systemd-timesyncd`

- **ری‌لود Traefik بعد از آپلود گواهی** خودکار انجام نمی‌شه: ماژول دستور
  `docker compose -f /opt/ngcorion/docker-compose.yml restart traefik` رو اجرا می‌کنه،
  ولی کانتینر بک‌اند نه CLI داکر داره نه `/var/run/docker.sock` رو مانت کرده، و مسیر
  پروژه هم `/opt/ngcorion` نیست. پاسخ API این رو صادقانه گزارش می‌کنه
  (`proxy_reload.reloaded = false`) و آپلود گواهی با موفقیت انجام می‌شه؛ ری‌استارت رو
  دستی بزن:
  ```bash
  docker compose restart traefik
  ```
- گواهی آپلودشده در `/etc/ngcorion/certs/` ذخیره می‌شه، ولی Traefik گواهی‌اش رو از
  `traefik/certs/` می‌خونه (`traefik/dynamic/tls.yml`). برای این‌که گواهی آپلودشده
  واقعاً سرو بشه باید یا فایل‌ها رو به `traefik/certs/` کپی کنی یا مسیرهای `tls.yml` رو
  به گواهی جدید تغییر بدی و بعد Traefik رو ری‌استارت کنی.

### چک‌لیست تأیید روی سرور `172.16.200.90`

کارهایی که خودت باید روی سرور اجرا کنی تا مطمئن بشی سایت بالا میاد:

1. **آخرین تغییرات کد رو بگیر** (compose جدید، `app/main.py`، `tls.yml`):
   ```bash
   cd ~/netease && git pull
   ```
2. دامنه‌ی محلی رو به hosts اضافه کن و خط قدیمی `ngcorion.com` رو حذف کن:
   ```bash
   echo "172.16.200.90 ngcorion.local" | sudo tee -a /etc/hosts
   sudo sed -i '/ngcorion\.com/d' /etc/hosts
   ```
   (اگه از یه کلاینت دیگه تست می‌کنی، همین دو کار رو روی اون کلاینت هم انجام بده.)
3. **گواهی جدید رو روی سرور بساز** (گواهی‌ها تو گیت نیستن — بخش «گواهی SSL» بالا؛ اگه
   پوشه مالکش root باشه با sudo بزن، وگرنه گواهی ساخته نمی‌شه):
   ```bash
   sudo rm -f traefik/certs/ngcorion.crt traefik/certs/ngcorion.key
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout traefik/certs/ngcorion.local.key \
     -out traefik/certs/ngcorion.local.crt \
     -subj "/C=IR/ST=Tehran/L=Tehran/O=NGCorion/CN=ngcorion.local" \
     -addext "subjectAltName=IP:172.16.200.90,DNS:ngcorion.local"
   ls -l traefik/certs/   # هر دو فایل .crt و .key باید باشن و خالی نباشن
   ```
4. **فرانت رو build کن** (اگه build با خطای permission خورد، اول `sudo rm -rf front/dist`):
   ```bash
   cd front && npm install && npm run build && cd ..
   ```
5. کانتینرها رو بالا بیار — `--remove-orphans` کانتینر قدیمی `frontend` (nginx) رو حذف می‌کنه:
   ```bash
   docker compose up -d --remove-orphans
   ```
6. سلامت سرویس‌ها رو چک کن: `docker compose ps` (باید `Up`/healthy باشن؛ دیگه **نباید**
   کانتینری به اسم `frontend` باشه).
7. تست بک‌اند: `curl -k https://ngcorion.local/health` → باید `{"status":"ok",...}` بده.
8. تست فرانت: `curl -k https://ngcorion.local/` → باید HTML صفحه‌ی React (`index.html`)
   برگرده.
9. تست ریدایرکت HTTP→HTTPS: `curl -kI http://ngcorion.local/` → باید `308` و
   `Location: https://ngcorion.local/` بده.
10. تو مرورگر برو `https://ngcorion.local` و هشدار گواهی self-signed رو Accept کن.
11. پیش‌نیازهای System Configuration رو انجام بده (بخش «پیش‌نیازهای System Configuration»
    بالا): ساختن `/etc/ngcorion/certs`، نصب `snmpd` و `rsyslog`، و
    `sudo touch /etc/systemd/timesyncd.conf` — بعدش `docker compose up -d backend`.
    تست: `curl -k https://ngcorion.local/api/system/time -H "Authorization: Bearer <token>"`
    باید تنظیمات ذخیره‌شده و ساعت فعلی سرور رو برگردونه.
