# Deployment Guide

## راه‌اندازی با دامنه و HTTPS

این پروژه با دامنه `ngcorion.com` و روی سرور با IP `172.16.200.90` بالا میاد. مسیریابی و
HTTPS (با گواهی self-signed) به‌طور کامل توسط **Traefik** انجام می‌شه — فرانت (بیلد شده‌ی
React) رو یک کانتینر nginx داخلی سرو می‌کنه که فقط از طریق Traefik در دسترسه (پورتی به
هاست باز نمی‌کنه)، و بک‌اند هم فقط داخل شبکه‌ی داکر در دسترسه.

آدرس‌دهی:
- `https://ngcorion.com/` → فرانت (React build)
- `https://ngcorion.com/api/...` و `https://ngcorion.com/auth/...` → بک‌اند (FastAPI)
- `https://ngcorion.com/docs` → مستندات Swagger بک‌اند

### مراحل روی سرور

1. **اضافه کردن دامنه به hosts** (چون DNS واقعی نداره):
   ```
   echo "172.16.200.90 ngcorion.com" | sudo tee -a /etc/hosts
   ```
   این خط رو روی هر کامپیوتری که می‌خواد به سایت وصل بشه باید اجرا کنی (هم روی خود
   سرور اگه از طریق دامنه تستش می‌کنی، هم روی کلاینت‌ها).

2. **گواهی SSL**: از قبل تو `traefik/certs/ngcorion.crt` و `traefik/certs/ngcorion.key`
   ساخته شده (self-signed، معتبر برای دامنه‌ی `ngcorion.com` و IP `172.16.200.90`، اعتبار
   ۱ ساله). اگه لازم شد از نو بسازیش:
   ```bash
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout traefik/certs/ngcorion.key \
     -out traefik/certs/ngcorion.crt \
     -subj "/C=IR/ST=Tehran/L=Tehran/O=NGCorion/CN=ngcorion.com" \
     -addext "subjectAltName=IP:172.16.200.90,DNS:ngcorion.com"
   ```

3. **Build فرانت**:
   ```bash
   cd /path/to/project
   cd front && npm install && npm run build && cd ..
   ```
   خروجی می‌ره تو `front/dist/` که مستقیم توسط کانتینر `frontend` (nginx:alpine) سرو
   می‌شه. بعد از هر تغییر تو کد فرانت، این مرحله باید دوباره اجرا بشه — دایرکتوری
   `dist/` تو gitignore هست و در ری‌است تازه ساخته نمی‌شه.

4. **اجرای داکر**:
   ```bash
   docker compose up -d
   ```

5. **آدرس‌ها**:
   - سایت اصلی: `https://ngcorion.com`
   - مستندات API (Swagger UI): `https://ngcorion.com/docs`
   - API base: `https://ngcorion.com/api/...`

   (مرورگر برای گواهی self-signed هشدار می‌ده — Advanced → Accept / Proceed)

### نکات فنی

- فرانت (`src/config/api.js`) از `baseURL` نسبی (`''`) استفاده می‌کنه و مسیرهای
  `/api/...` و `/auth/...` رو خودش کامل می‌سازه؛ یعنی همیشه هم‌مبدأ (same-origin) با
  دامنه‌ای که سایت روش سرو می‌شه صحبت می‌کنه. نیازی به ست کردن یک API URL مطلق تو کد
  یا build نیست — مسیریابی `/api`، `/auth`، `/docs`، `/openapi.json` و `/static` به
  بک‌اند کاملاً روی Traefik (`docker-compose.yml`, لیبل‌های سرویس `backend`) تعریف شده.
- درخواست HTTP ساده به `ngcorion.com` (پورت ۸۰) خودکار ریدایرکت می‌شه به HTTPS.
- بک‌اند هیچ پورتی رو مستقیم به هاست باز نمی‌کنه (`expose: ["8000"]`)؛ فقط از داخل
  شبکه‌ی داکر (توسط Traefik) در دسترسه.
- تنظیمات دیگه‌ی سرویس‌ها (`license-server`, `license-admin`, دیتابیس‌ها) و مسیریابی
  dev قبلی (`netease.localhost` روی Traefik، پورت ۸۰) دست‌نخورده باقی مونده و تحت تأثیر
  این تغییرات نیستن.
