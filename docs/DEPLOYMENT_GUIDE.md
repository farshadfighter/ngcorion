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

2. **گواهی SSL**: از قبل تو `traefik/certs/ngcorion.local.crt` و
   `traefik/certs/ngcorion.local.key` ساخته شده (self-signed، معتبر برای دامنه‌ی
   `ngcorion.local` و IP `172.16.200.90`، اعتبار ۱ ساله). اگه لازم شد از نو بسازیش:
   ```bash
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout traefik/certs/ngcorion.local.key \
     -out traefik/certs/ngcorion.local.crt \
     -subj "/C=IR/ST=Tehran/L=Tehran/O=NGCorion/CN=ngcorion.local" \
     -addext "subjectAltName=IP:172.16.200.90,DNS:ngcorion.local"
   ```

3. **Build فرانت**:
   ```bash
   cd /path/to/project
   cd front && npm install && npm run build && cd ..
   ```
   خروجی می‌ره تو `front/dist/` که به‌صورت read-only داخل کانتینر `backend` مانت می‌شه
   (`./front/dist:/app/front/dist:ro`) و توسط FastAPI سرو می‌شه. بعد از هر تغییر تو کد
   فرانت، این مرحله باید دوباره اجرا بشه — دایرکتوری `dist/` تو gitignore هست و در ری‌است
   تازه ساخته نمی‌شه.

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

### چک‌لیست تأیید روی سرور `172.16.200.90`

کارهایی که خودت باید روی سرور اجرا کنی تا مطمئن بشی سایت بالا میاد:

1. دامنه‌ی محلی رو به hosts اضافه کن:
   ```bash
   echo "172.16.200.90 ngcorion.local" | sudo tee -a /etc/hosts
   ```
   (اگه از یه کلاینت دیگه تست می‌کنی، همین خط رو روی اون کلاینت هم اضافه کن.)
2. اگه خط قدیمی `ngcorion.com` تو `/etc/hosts` مونده، حذفش کن تا تداخل نشه.
3. فرانت رو build کن: `cd front && npm install && npm run build && cd ..`
4. کانتینرها رو بالا بیار: `docker compose up -d`
5. سلامت سرویس‌ها رو چک کن: `docker compose ps` (همه باید `Up`/healthy باشن؛ دیگه
   کانتینری به اسم `frontend` وجود نداره).
6. تست بک‌اند: `curl -k https://ngcorion.local/health` → باید `{"status":"ok",...}` بده.
7. تست فرانت: `curl -k https://ngcorion.local/` → باید HTML صفحه‌ی React (`index.html`)
   برگرده.
8. تست ریدایرکت HTTP→HTTPS: `curl -kI http://ngcorion.local/` → باید `308` و
   `Location: https://ngcorion.local/` بده.
9. تو مرورگر برو `https://ngcorion.local` و هشدار گواهی self-signed رو Accept کن.
