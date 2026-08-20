# انتقال License Server به سرور جداگانه

> این سند حاصل ممیزی کد فعلی (`docker-compose.yml`، `app/core/*`، `license_server/*`) است و
> فقط برای **اجرای دستی** نوشته شده — هیچ انتقالی به‌صورت خودکار انجام نمی‌شود.
> فایل‌های همراه این راهنما:
> - `deploy/docker-compose.license.yml` — استک آمادهٔ سرور لایسنس
> - `deploy/.env.license.example` — نمونهٔ متغیرهای محیطی سرور لایسنس

---

## ۰. خلاصهٔ وضعیت فعلی (نتیجهٔ ممیزی)

| پرسش | پاسخ |
|---|---|
| ارتباط backend با license-server چگونه است؟ | **فقط HTTP/REST** از طریق `app/core/license_client.py` (کتابخانهٔ `requests`). هیچ دیتابیس یا Redis مشترکی در کد وجود ندارد. |
| اگر license-server در دسترس نباشد چه می‌شود؟ | برنامه crash نمی‌کند. با اصلاحات این نسخه: timeout صریح، ۳ بار retry، حفظ آخرین وضعیت معتبر تا ۴۸ ساعت، و خطای `503` با پیام روشن به‌جای `500`. |
| فرض hardcoded روی localhost وجود دارد؟ | داشت (`LICENSE_SERVER_URL` پیش‌فرض `http://localhost:8001` بود). حذف شد؛ حالا **فقط** از متغیر محیطی خوانده می‌شود و اگر ست نشده باشد، برنامه در startup با پیام واضح متوقف می‌شود. |
| Redis یا Postgres مشترک است؟ | Postgres کاملاً جدا (`postgres` و `postgres-license`). Redis یک instance مشترک بود ولی **کلیدها جدا**: app روی DB=0 و license-server روی DB=1. ضمناً هیچ کدی در `app/` از Redis استفاده نمی‌کند؛ پس Redis می‌تواند کامل همراه سرور لایسنس برود. |
| رمز مشترکی بین دو سرویس هست؟ | بله، ولی **نه `SECRET_KEY`**. رمز مشترک واقعی `organization_token` است که هنگام activate صادر و در سمت app به‌صورت رمزنگاری‌شده در `/root/.license` ذخیره می‌شود و امضای HMAC-SHA256 درخواست‌های `validate` / `consume` را می‌سازد. |

---

## ۱. معماری هدف

```
        ┌──────────────────────────── App Server ────────────────────────────┐
        │                                                                    │
        │  traefik :80/:443                                                  │
        │      │                                                             │
        │      ▼                                                             │
        │  backend :8000  ──────────┐        postgres  (netease_db)          │
        │   (NGCorion API + SPA)    │        redis     (DB 0، فعلاً بلااستفاده)│
        │      │                    │                                        │
        │      │ /root/.license     │                                        │
        │      │ (license_key +     │                                        │
        │      │  organization_token│                                        │
        │      │  + vm_fingerprint) │                                        │
        └──────┼────────────────────┼────────────────────────────────────────┘
               │                    │
               │  HTTP  :8001       │  HMAC-SHA256 با organization_token
               │  POST /api/licenses/validate                (هر status/heartbeat)
               │  POST /api/licenses/consume                 (هر audit / harden)
               │  POST /api/licenses/heartbeat               (هر ۱ ساعت)
               ▼
        ┌────────────────────────── License Server ──────────────────────────┐
        │                                                                    │
        │  license-server :8001 ──┬── postgres-license (license_db)          │
        │  (FastAPI)              └── redis (DB 1 — فقط rate limit)          │
        │                                                                    │
        │  [اختیاری] traefik :443 برای HTTPS                                 │
        └────────────────────────────────────────────────────────────────────┘
```

نکته‌های معماری:

- تمام ارتباط **یک‌طرفه** است: app به license-server وصل می‌شود، هرگز برعکس.
  یعنی روی سرور لایسنس فقط باید پورت **8001** برای IP سرور app باز باشد.
- `postgres-license` و `redis` سرور لایسنس **نباید** روی هاست publish شوند؛ فقط داخل شبکهٔ داکر.
- `license-admin` (پنل مدیریت لایسنس) یک UI روی همان API است و حالا **بخشی از استک سرور
  لایسنس** است (پورت 5174). فقط برای IP ادمین باز شود — بخش ۸.

---

## ۲. پیش‌نیازها

- سرور جدید با Ubuntu 22.04+ (یا هر توزیع با kernel جدید و Docker پشتیبانی‌شده)
- Docker Engine 24+ و Docker Compose v2
- دسترسی شبکه بین دو سرور روی پورت **8001** (TCP، از app → license)
- همگام بودن ساعت هر دو سرور (NTP) — **الزامی**، توضیح در بخش «نکات مهم»
- دسترسی به مقادیر فعلی: `LICENSE_SERVER_SECRET_KEY`، `ADMIN_PASSWORD` و رمز دیتابیس لایسنس
- فضای دیسک برای dump دیتابیس لایسنس (معمولاً چند مگابایت)

---

## ⚠️ ۳. مهم‌ترین نکتهٔ پیش از شروع — VM Fingerprint

این بخش پاسخ پرسش «آیا لایسنس باید دوباره activate شود؟» است.

**چطور کار می‌کند:**

1. هنگام activate، سمت app این را صدا می‌زند: `GET /api/fingerprint` روی **license-server**
   (`app/core/license_client.py` → `get_fingerprint()`).
   یعنی fingerprint از سخت‌افزار/هویت **ماشین سرور لایسنس** ساخته می‌شود، نه سرور app.
2. همان مقدار در دو جا ذخیره می‌شود:
   - سمت app: رمزنگاری‌شده در `/root/.license/.license.dat` (والیوم `license_client_data`)
   - سمت license: ستون `licenses.vm_fingerprint` در `license_db`
3. در `validate` / `consume` / `heartbeat`، app همان مقدار **ذخیره‌شده** را می‌فرستد و سرور
   با ستون دیتابیس مقایسه می‌کند (`crud.validate_license`). مقدار جدید محاسبه نمی‌شود.

**نتیجه برای انتقال:**

| سناریو | نتیجه |
|---|---|
| والیوم `license_client_data` سرور app دست‌نخورده بماند **و** `license_db` با dump/restore منتقل شود | ✅ نیازی به activate مجدد **نیست**. دو مقدار همچنان با هم برابرند و لایسنس بدون وقفه کار می‌کند. |
| روی سرور app دوباره activate کنید (یا والیوم لایسنس پاک شود) | ❌ خطا: `this license already activate in another VM` — چون `/api/fingerprint` سرور جدید مقدار تازه‌ای می‌دهد ولی دیتابیس مقدار قدیمی را نگه داشته. |

**دو قانون طلایی:**

```bash
# ۱) روی سرور app هرگز والیوم لایسنس را پاک نکنید:
#    docker compose down -v   ← ممنوع (والیوم license_client_data و کل لایسنس فعال را پاک می‌کند)
     docker compose down      ← درست

# ۲) دیتابیس license_db را با مقادیر ستون vm_fingerprint منتقل کنید (dump کامل، نه schema-only)
```

**اگر مجبور به activate مجدد شدید** (مثلاً والیوم از دست رفت)، ابتدا باید fingerprint قدیمی
در دیتابیس لایسنس پاک شود — endpoint آماده‌ای برای این کار وجود ندارد، پس با SQL:

```bash
# روی سرور لایسنس (جدید)
docker compose exec postgres-license psql -U license_user -d license_db \
  -c "UPDATE licenses SET vm_fingerprint = NULL, activated_at = NULL WHERE license_key = '<LICENSE_KEY>';"

# سپس از سمت app یک بار activate کنید (UI: صفحهٔ License، یا مستقیم API):
curl -k -X POST https://APP_SERVER_IP/api/license/activate \
     -H 'Content-Type: application/json' \
     -d '{"license_key":"<LICENSE_KEY>"}'
```

**نکتهٔ تکمیلی:** fingerprint داخل **کانتینر** license-server محاسبه می‌شود (MAC کارت شبکهٔ
کانتینر + `/etc/machine-id` ایمیج + hostname کانتینر). یعنی با بازساخت کانتینر هم می‌تواند
تغییر کند. قبل و بعد از هر تغییر، مقدار را مقایسه کنید:

```bash
# مقدار فعلی سرور لایسنس
curl -s http://LICENSE_SERVER_IP:8001/api/fingerprint

# مقدار ثبت‌شده در دیتابیس لایسنس
docker compose exec postgres-license psql -U license_user -d license_db \
  -c "SELECT license_key, vm_fingerprint, activated_at FROM licenses;"

# مقداری که سرور app ذخیره کرده (روی سرور app اجرا کنید)
docker compose exec backend python -c \
 "from app.core.license_client import SecureStorage; d=SecureStorage('~/.license').load_license() or {}; print(d.get('vm_fingerprint'))"
```

اگر «مقدار ثبت‌شده در دیتابیس» و «مقداری که سرور app ذخیره کرده» یکی باشند، انتقال بدون
activate مجدد انجام می‌شود — حتی اگر مقدار `/api/fingerprint` سرور جدید متفاوت باشد.

---

## ۴. مرحله ۱ — آماده‌سازی سرور license

### ۱-۱. نصب Docker روی سرور جدید

```bash
# Ubuntu 22.04+
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
docker --version && docker compose version

# همگام‌سازی ساعت (برای امضای HMAC حیاتی است)
sudo timedatectl set-ntp true
timedatectl status
```

### ۱-۲. کپی فایل‌های لازم از سرور app

روی **سرور app** (در مسیر پروژه):

```bash
tar czf /tmp/license-stack.tgz \
    license_server/ \
    license-admin-ui/ \
    db/postgres-license/init.sql \
    db/redis/redis.conf \
    deploy/docker-compose.license.yml \
    deploy/.env.license.example

scp /tmp/license-stack.tgz root@LICENSE_SERVER_IP:/tmp/
```

روی **سرور لایسنس**:

```bash
sudo mkdir -p /opt/ngcorion-license
cd /opt/ngcorion-license
sudo tar xzf /tmp/license-stack.tgz
sudo mv deploy/docker-compose.license.yml ./docker-compose.yml
sudo mv deploy/.env.license.example ./.env
sudo rmdir deploy 2>/dev/null || true

# فایل‌های زائد را نبرید/پاک کنید (مقادیر نمونه‌اند، ولی روی سرور جایی ندارند)
sudo rm -f license_server/.env.bak.* license_server/.env

ls -R /opt/ngcorion-license | head -20
```

### ۱-۳. انتقال دیتابیس لایسنس (pg_dump + restore)

روی **سرور app قدیمی** (استک هنوز بالا است):

```bash
# دامپ کامل و قابل‌تکرار (شامل ستون vm_fingerprint و شمارنده‌های مصرف)
docker compose exec -T postgres-license \
  pg_dump -U license_user -d license_db --clean --if-exists --no-owner \
  > /tmp/license_db_$(date +%F).sql

# صحت دامپ را ببینید (باید ردیف‌های licenses را داشته باشد)
grep -c "INSERT INTO\|COPY public.licenses" /tmp/license_db_*.sql

scp /tmp/license_db_*.sql root@LICENSE_SERVER_IP:/tmp/
```

روی **سرور لایسنس**، بعد از تنظیم `.env` (مرحلهٔ ۱-۴) و بالا آوردن دیتابیس:

```bash
cd /opt/ngcorion-license
docker compose up -d postgres-license
docker compose exec postgres-license pg_isready -U license_user -d license_db

# restore
docker compose exec -T postgres-license psql -U license_user -d license_db < /tmp/license_db_*.sql

# راستی‌آزمایی: باید همان تعداد لایسنس و همان fingerprint را ببینید
docker compose exec postgres-license psql -U license_user -d license_db \
  -c "SELECT license_key, plan_type, is_active, vm_fingerprint, used_audits, used_hardens, expires_at FROM licenses;"
```

> اگر نصب کاملاً تازه است (بدون dump): جدول‌ها را خود `license-server` در اولین اجرا
> با `Base.metadata.create_all()` می‌سازد. در آن حالت بعد از بالا آمدن سرویس یک بار
> `docker compose exec license-server alembic stamp head` بزنید تا Alembic با
> وضعیت واقعی هماهنگ شود (وگرنه `upgrade head` می‌خواهد ایندکس‌های موجود را دوباره بسازد).

### ۱-۴. Redis

Redis سرور لایسنس فقط شمارندهٔ rate limit را نگه می‌دارد (`db/redis/redis.conf` →
`save ""` و `appendonly no`). **هیچ داده‌ای برای انتقال ندارد** — یک instance تازه کافی است.
تنها نکته: این Redis نباید روی هاست publish شود (در compose فقط `expose` شده است).

### ۱-۵. تنظیم متغیرهای محیطی

```bash
cd /opt/ngcorion-license
sudo chmod 600 .env
sudo nano .env
```

مقادیری که **باید** پر شوند:

| متغیر | توضیح |
|---|---|
| `LICENSE_DB_PASSWORD` | همان رمز دیتابیس لایسنس در استک قبلی (پیش‌فرض قدیمی: `license1234`). اگر رمز جدیدی می‌گذارید، بعد از restore با `ALTER USER license_user WITH PASSWORD '...';` هماهنگش کنید. |
| `LICENSE_SERVER_SECRET_KEY` | **همان مقدار سرور قبلی**. فقط JWTهای پنل ادمین را امضا می‌کند؛ اگر عوض شود، ارتباط app با لایسنس مشکلی پیدا نمی‌کند ولی نشست‌های ادمین باطل می‌شوند. |
| `LICENSE_ADMIN_USERNAME` / `LICENSE_ADMIN_PASSWORD` | نام‌کاربری/رمز ورود پنل ادمین (`POST /api/admin/login` → توکن JWT). مقدار قدیمی `admin` / `12qw!@QW` بود — **حتماً عوض شود**. |
| `LICENSE_BIND_ADDR` | ترجیحاً IP خصوصی‌ای که سرور app از آن می‌بیند، نه `0.0.0.0`. |

---

## ۵. مرحله ۲ — docker-compose سرور license

فایل آماده: **`deploy/docker-compose.license.yml`** (روی سرور لایسنس به `docker-compose.yml` تغییر نام داده شد).

فقط شامل سرویس‌های زیر است:

- `postgres-license` — دیتابیس لایسنس (فقط `expose`، publish نشده)
- `redis` — instance اختصاصی، DB 1، بدون persistence
- `license-server` — API روی پورت 8001 با healthcheck
- `license-admin` — پنل ادمین (بیلد production؛ nginx روی پورت 5174)
- `traefik` — **اختیاری**، فقط با profile فعال می‌شود

اجرا:

```bash
cd /opt/ngcorion-license

# بدون HTTPS (پیش‌فرض)
docker compose up -d --build

# با HTTPS (نیازمند traefik/certs و traefik/dynamic/tls.yml از سرور app)
docker compose --profile tls up -d --build

docker compose ps
docker compose logs -f license-server
```

متغیرهایی که compose بدون آن‌ها **بالا نمی‌آید** (عمداً بدون مقدار پیش‌فرض):
`LICENSE_SERVER_SECRET_KEY`، `LICENSE_ADMIN_PASSWORD`، `LICENSE_DB_PASSWORD`.

---

## ۶. مرحله ۳ — آپدیت سرور اصلی

> ✅ **این مرحله در مخزن انجام شده است.** `docker-compose.yml` سرور app دیگر
> سرویس‌های `license-server`، `postgres-license` و `license-admin` (و والیوم‌های
> `postgres_license_data` و `license_admin_node_modules`) را ندارد. فقط
> `traefik`، `backend`، `postgres` و `redis` باقی مانده‌اند و والیوم
> `license_client_data` — که **لایسنس فعال را نگه می‌دارد** — دست‌نخورده است.
> کاری که روی سرور باقی می‌ماند، فقط تنظیم `.env` و ری‌استارت است.

وضعیت فعلی `docker-compose.yml` سرور app:

```yaml
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      # license-server حذف شده است

    environment:
      ...
      LICENSE_SERVER_URL: ${LICENSE_SERVER_URL}    # بدون مقدار پیش‌فرض
```

۱. آدرس سرور لایسنس را در فایل `.env` سرور app ست کنید — چون مقدار پیش‌فرضی وجود ندارد،
این تنها مرحلهٔ الزامی است:

```bash
cd /path/to/ngcorion
echo 'LICENSE_SERVER_URL=http://NEW_LICENSE_SERVER_IP:8001' >> .env
docker compose config | grep LICENSE_SERVER_URL      # باید IP جدید را نشان بدهد
```

اگر این متغیر ست نشده باشد، `docker compose` هشدار «variable is not set» می‌دهد و
backend هنگام startup با پیام `RuntimeError: LICENSE_SERVER_URL is not set ...` بالا
نمی‌آید. اگر ترجیح می‌دهید خطا زودتر و در سطح compose رخ بدهد، در `docker-compose.yml`
مقدار را به این شکل بنویسید:

```yaml
      LICENSE_SERVER_URL: ${LICENSE_SERVER_URL:?set LICENSE_SERVER_URL in .env}
```

۲. سرویس `redis` سرور app: کد فعلی برنامه از Redis استفاده نمی‌کند و بعد از جدا شدن
license-server هیچ مصرف‌کننده‌ای ندارد. می‌توانید نگهش دارید (بی‌ضرر) یا حذفش کنید.

۳. پنل ادمین لایسنس (`license-admin`) دیگر روی سرور app اجرا نمی‌شود؛ حالا بخشی از
استک سرور لایسنس است. جزئیات دسترسی در بخش ۸.

۴. اعمال تغییرات — **بدون `-v`**:

```bash
docker compose config >/dev/null          # اعتبارسنجی فایل
docker compose up -d --force-recreate backend
docker compose logs -f backend | grep -i license
```

در لاگ استارتاپ باید ببینید:

```
[Startup] license server: http://NEW_LICENSE_SERVER_IP:8001
```

اگر `LICENSE_SERVER_URL` ست نشده باشد، برنامه عمداً بالا نمی‌آید و این خطا را می‌دهد:

```
RuntimeError: LICENSE_SERVER_URL is not set. Point it at the license server, ...
```

---

## ۷. مرحله ۴ — تست اتصال

```bash
# ۱) سلامت خود سرور لایسنس (روی خود سرور لایسنس)
curl -s http://127.0.0.1:8001/health
# → {"status":"healthy"}

# ۲) دسترسی شبکه از سرور app به سرور لایسنس (روی سرور app)
curl -s http://NEW_LICENSE_SERVER_IP:8001/health
curl -s http://NEW_LICENSE_SERVER_IP:8001/api/fingerprint

# ۳) همین تست از داخل کانتینر backend (DNS/شبکهٔ داکر را هم می‌سنجد)
docker compose exec backend python -c \
 "import requests,os; print(requests.get(os.environ['LICENSE_SERVER_URL']+'/health', timeout=5).json())"

# ۴) وضعیت لایسنس از دید برنامه (بدون احراز هویت قابل فراخوانی است)
curl -k -s https://APP_SERVER_IP/api/license/status | python3 -m json.tool
```

خروجی مورد انتظار مرحلهٔ ۴:

```json
{
    "valid": true,
    "plan_type": "plan_100",
    "is_pilot_mode": false,
    "message": "...",
    "limits": {"max_audits": 100, "max_hardens": 100},
    "usage": {"used_audits": 12, "used_hardens": 3}
}
```

تفسیر خروجی‌های نادرست:

| نشانه | معنی | اقدام |
|---|---|---|
| `"valid": false` + پیام `VM fingerprint is not match` | dump با مقدار fingerprint منتقل نشده یا لایسنس دوباره activate شده | بخش ۳ همین سند |
| پاسخ `503` با `license_server_unreachable` | مشکل شبکه/فایروال؛ لایسنس سالم است | پورت 8001 و مسیر شبکه را چک کنید |
| `"valid": false` + `Invalid signature` روی `consume` | اختلاف ساعت دو سرور بیش از ۵ دقیقه | NTP هر دو سرور |
| `429 Too Many Requests` | rate limit سرور لایسنس (پیش‌فرض ۶۰/دقیقه برای هر IP) | `LICENSE_RATE_LIMIT_PER_MINUTE` را بالا ببرید |

تست انتها-به-انتها (اختیاری ولی توصیه‌شده): یک audit کوچک از UI اجرا کنید و ببینید
`used_audits` در `/api/license/status` یک واحد بالا می‌رود — یعنی مسیر `consume` و امضای HMAC سالم است.

---

## ۸. دسترسی به پنل ادمین لایسنس (license-admin)

پنل ادمین حالا داخل استک سرور لایسنس اجرا می‌شود: باندل production با Vite ساخته و با
nginx سرو می‌شود (`license-admin-ui/Dockerfile.prod`). دیگر خبری از سرور توسعهٔ Vite نیست.

- **آدرس:** `http://LICENSE_SERVER_IP:5174`
- **نام‌کاربری / رمز:** از فایل `.env` سرور لایسنس می‌آید —
  `LICENSE_ADMIN_USERNAME` و `LICENSE_ADMIN_PASSWORD`
  (همان مقادیری که به سرویس `license-server` داده می‌شوند)

```bash
# روی سرور لایسنس
cd /opt/ngcorion-license
docker compose up -d --build license-admin
docker compose ps license-admin
```

**نحوهٔ ارتباط پنل با API:** آدرس سرور لایسنس داخل جاوااسکریپت باندل نمی‌شود. کلاینت
مسیرهای نسبی (`/api/...` و `/health`) را صدا می‌زند و nginx آن‌ها را داخل شبکهٔ داکر به
`http://license-server:8001` پروکسی می‌کند (`license-admin-ui/nginx.conf`). یعنی same-origin،
بدون CORS، و بدون نیاز به rebuild اگر IP سرور عوض شود.

**احراز هویت:** ورود از طریق `POST /api/admin/login` انجام می‌شود و یک توکن **JWT**
برمی‌گرداند (امضا شده با `LICENSE_SERVER_SECRET_KEY`)؛ بقیهٔ فراخوانی‌های ادمین با هدر
`Authorization: Bearer <token>` می‌روند. HTTP Basic روی این endpointها کار **نمی‌کند**.
معادل خط فرمانِ همان کاری که پنل انجام می‌دهد:

```bash
TOKEN=$(curl -s -X POST http://LICENSE_SERVER_IP:8001/api/admin/login \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$LICENSE_ADMIN_USERNAME\",\"password\":\"$LICENSE_ADMIN_PASSWORD\"}" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -H "Authorization: Bearer $TOKEN" \
     http://LICENSE_SERVER_IP:8001/api/admin/licenses | python3 -m json.tool
```

> ⚠️ **پورت 5174 را روی اینترنت باز نگذارید.** این رابط، لایسنس صادر می‌کند. در بخش ۹
> فقط IP ادمین اجازهٔ دسترسی می‌گیرد. برای HTTPS، profile `tls` را فعال کنید و از
> `LICENSE_ADMIN_HOSTNAME` استفاده کنید.

---

## ۹. مرحله ۵ — Firewall

روی **سرور لایسنس** فقط IP سرور app اجازهٔ پورت 8001 داشته باشد:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from YOUR_ADMIN_IP to any port 22 proto tcp     # اول SSH را باز کنید!
sudo ufw allow from APP_SERVER_IP to any port 8001 proto tcp
sudo ufw enable
sudo ufw status numbered
```

پنل ادمین (`license-admin`، پورت 5174) روی همین سرور اجرا می‌شود — دسترسی به آن را فقط
برای IP ادمین باز کنید، نه برای سرور app:

```bash
sudo ufw allow from YOUR_ADMIN_IP to any port 5174 proto tcp   # یا 443 در حالت TLS
```

نکته: `docker` قواعد خودش را مستقیم در `iptables` (زنجیرهٔ `DOCKER-USER`) می‌نویسد و
می‌تواند `ufw` را دور بزند. برای اطمینان، پورت را روی IP خصوصی bind کنید
(`LICENSE_BIND_ADDR` در `.env`) و از بیرون تست کنید:

```bash
# از یک ماشین سوم — نباید پاسخ بدهد
curl -m 5 http://LICENSE_SERVER_IP:8001/health
```

---

## ۱۰. بازگشت به عقب (Rollback)

اگر بعد از انتقال مشکلی پیش آمد:

```bash
# روی سرور app
sed -i '/^LICENSE_SERVER_URL=/d' .env        # برگشت به مقدار پیش‌فرض compose
git checkout docker-compose.yml              # بازگرداندن سرویس‌های license
docker compose up -d
```

چون والیوم `license_client_data` و `postgres_license_data` سرور app دست‌نخورده مانده‌اند،
همان لایسنس قبلی بلافاصله دوباره کار می‌کند. **به همین دلیل تا وقتی انتقال کاملاً تثبیت نشده،
والیوم‌های سرور app را پاک نکنید.**

---

## ۱۱. نکات مهم

1. **`SECRET_KEY` نیازی به یکسان بودن بین دو سرور ندارد.** برخلاف تصور رایج، رمز مشترکِ
   بین app و license-server مقدار `organization_token` هر لایسنس است (امضای HMAC-SHA256 در
   `app/core/license_client.py` و `license_server/app/utils/signing.py`).
   - `SECRET_KEY` سرور app → امضای JWT کاربران NGCorion
   - `SECRET_KEY` سرور لایسنس → امضای JWT پنل ادمین لایسنس
   یکسان نگه‌داشتن `LICENSE_SERVER_SECRET_KEY` با مقدار قبلی فقط برای بی‌اعتبار نشدن
   نشست‌های ادمین توصیه می‌شود.

2. **ساعت دو سرور باید همگام باشد (NTP).** امضای درخواست‌ها یک timestamp دارد و سرور
   لایسنس هر امضای قدیمی‌تر از **۳۰۰ ثانیه** را رد می‌کند (`verify_signature(max_age_seconds=300)`).
   دقت کنید ماژول System Configuration خودِ NGCorion می‌تواند ساعت هاست را با `timedatectl`
   تغییر دهد — یک تنظیم اشتباه، کل `validate`/`consume` را با `Invalid signature` می‌خواباند.

3. **قبل از انتقال از دیتابیس لایسنس backup بگیرید** (بخش ۱-۳) و dump را جای امنی نگه دارید؛
   شمارنده‌های `used_audits` / `used_hardens` و `vm_fingerprint` فقط همان‌جا هستند.

4. **آیا لایسنس باید دوباره activate شود؟ خیر** — به شرط اینکه والیوم `license_client_data`
   سرور app دست‌نخورده بماند و dump دیتابیس (با ستون `vm_fingerprint`) restore شود.
   جزئیات و راه‌حلِ حالت استثنا در بخش ۳.

5. **رفتار قطعی ارتباط (بعد از اصلاحات این نسخه):**
   - هر فراخوانی timeout صریح دارد: connect ۵ ثانیه، read ۱۰ ثانیه.
   - خطاهای اتصال تا ۳ بار retry می‌شوند؛ read-timeout روی `POST /consume` عمداً retry
     **نمی‌شود** تا سهمیهٔ مشتری دوبار مصرف نشود.
   - تا `LICENSE_OFFLINE_GRACE_HOURS` (پیش‌فرض ۴۸ ساعت) آخرین وضعیت معتبر حفظ می‌شود و
     برنامه کار می‌کند؛ بعد از آن fail-closed می‌شود.
   - در زمان قطعی، API خطای `503` با `license_server_unreachable: true` برمی‌گرداند
     (نه `403` گمراه‌کنندهٔ «لایسنس ندارید»).

6. **rate limit را بازبینی کنید.** سرور لایسنس بر اساس IP کلاینت محدود می‌کند و بعد از
   جداسازی، تمام ترافیک برنامه از **یک IP** می‌آید. اگر تعداد کاربران هم‌زمان زیاد است،
   `LICENSE_RATE_LIMIT_PER_MINUTE` را افزایش دهید.

7. **HTTP یا HTTPS؟** اگر دو سرور روی شبکهٔ خصوصی/VPN هستند، `http://IP:8001` کافی است
   (محتوای درخواست‌ها با HMAC امضا می‌شود، ولی رمزنگاری نمی‌شود). اگر ترافیک از اینترنت عبور
   می‌کند، حتماً profile `tls` را فعال و `LICENSE_SERVER_URL` را `https://...` کنید.

8. **`CORS` سرور لایسنس روی `["*"]` است** (`license_server/app/main.py`). چون این سرویس
   نباید مستقیماً از مرورگر کاربران صدا زده شود، محدود کردن آن به دامنهٔ پنل ادمین
   یک سخت‌سازی مناسب بعد از انتقال است.

9. **مانیتورینگ حداقلی:** یک چک دوره‌ای روی `http://LICENSE_SERVER_IP:8001/health` بگذارید.
   قطعی طولانی‌تر از ۴۸ ساعت باعث می‌شود کل برنامه fail-closed شود.

---

## ۱۲. چک‌لیست نهایی

- [ ] backup از `license_db` گرفته و در جای امن نگه‌داری شد
- [ ] fingerprint دیتابیس با fingerprint ذخیره‌شدهٔ سمت app مقایسه و یکسان بودنش تأیید شد
- [ ] Docker و NTP روی سرور لایسنس نصب و فعال است
- [ ] `.env` سرور لایسنس با رمزهای **جدید و قوی** پر شده و `chmod 600` است
- [ ] استک لایسنس بالا آمده و `/health` پاسخ می‌دهد
- [ ] پنل ادمین روی `http://LICENSE_SERVER_IP:5174` بالا می‌آید و لاگین با مقادیر `.env` کار می‌کند
- [ ] دیتابیس restore شده و ردیف‌های `licenses` با مقادیر مصرف قابل مشاهده‌اند
- [ ] `LICENSE_SERVER_URL` در `.env` سرور app ست شده
- [ ] سرویس‌های `license-server` / `postgres-license` / `license-admin` از compose سرور app حذف شدند
- [ ] `depends_on` سرویس backend اصلاح شد
- [ ] backend ری‌استارت شد و در لاگ آدرس جدید لایسنس دیده می‌شود
- [ ] `GET /api/license/status` مقدار `valid: true` و شمارنده‌های درست برمی‌گرداند
- [ ] یک audit آزمایشی اجرا شد و `used_audits` افزایش یافت
- [ ] فایروال سرور لایسنس فقط IP سرور app را روی 8001 می‌پذیرد
- [ ] پورت 8001 از یک ماشین سوم قابل دسترس **نیست**
- [ ] پورت 5174 (پنل ادمین) فقط از IP ادمین قابل دسترس است
- [ ] والیوم‌های سرور app پاک نشده‌اند (`docker compose down -v` اجرا نشده)
