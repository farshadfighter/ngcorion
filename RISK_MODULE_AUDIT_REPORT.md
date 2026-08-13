# گزارش ممیزی و تکمیل بک‌اند ماژول Risk & Exposure Intelligence

**پروژه:** NGCorion  •  **تاریخ:** 2026-08-13  •  **شاخه:** main

## خلاصه‌ی مدیریتی

بک‌اند ماژول Risk از قبل به‌صورت **کامل و باکیفیت** پیاده‌سازی شده بود (مدل‌ها،
سرویس محاسبه، تریگرها، APIها، Permissionها، Audit Log، خروجی CSV/JSON و ۲۹ تست
سبز). ممیزی جز‌به‌جز طبق Phase 0–12 انجام شد و **۴ نقص واقعی** نسبت به مستند
طراحی یافت و رفع شد. پس از اصلاح، مجموعاً **۳۴ تست سبز** است.

نکته‌ی مهم: هیچ‌کدام از نقص‌ها روی صحت محاسبه‌ی امتیاز اثر نداشتند (موتور از
مقادیر پیش‌فرض کد fallback می‌گرفت)؛ نقص‌ها در سطح «قابل‌ویرایش‌بودن تنظیمات از
API» و «اعتبارسنجی ورودی» بودند.

---

## نقص‌های یافته‌شده و رفع‌شده

| # | نقص | بخش مستند | وضعیت قبل | اصلاح |
|---|-----|-----------|-----------|-------|
| 1 | تنظیمات `criticality_{low,medium,high,critical}_score` و `risk_level_*_threshold` در Seed درج نمی‌شدند، پس در `GET/PUT /settings` نه دیده و نه ویرایش می‌شدند | ۵ (Criticality قابل‌ویرایش)، ۱۰ (Threshold قابل‌تنظیم) | موتور از `DEFAULT_SETTINGS` کد fallback می‌گرفت؛ ولی اپراتور نمی‌توانست ویرایش کند | ۸ ردیف تنظیمات به `seed.py` اضافه و در DB درج شد (idempotent) |
| 2 | هنگام Exclude کردن پورت از محاسبه، `exclusion_reason` اجباری نبود | ۷ (اجباری در صورت Exclusion) | امکان Exclude بدون دلیل | اعتبارسنجی در `PUT /ports/{id}` اضافه شد (۴۰۰ اگر excluded و بدون دلیل) |
| 3 | تغییر Thresholdها Recalculate All را فعال نمی‌کرد | ۸ (تغییر Threshold باید Recalc را فعال کند) | فقط weight/normalization تریگر می‌کرد | تریگر Recalc در `PUT /settings` برای کلیدهای حاوی `threshold` گسترش یافت |
| 4 | نبود اعتبارسنجی «عدم Overlap» آستانه‌های سطح ریسک | ۱۰ (بدون Overlap) | مقادیر نامرتب پذیرفته می‌شد | اعتبارسنجی صعودی‌بودن اکید (medium < high < very_high < critical، بازه ۰–۱۰۰) در `PUT /settings` |

---

## فایل‌های تغییریافته

| فایل | تغییر |
|------|-------|
| `app/modules/risk/seed.py` | افزودن ۸ تنظیم: ۴ `criticality_*_score` + ۴ `risk_level_*_threshold` (همه `is_editable=True`) |
| `app/modules/risk/router.py` | ثابت `THRESHOLD_KEYS`؛ اعتبارسنجی اجباری‌بودن `exclusion_reason` در `update_port`؛ اعتبارسنجی صعودی‌بودن Thresholdها و گسترش تریگر Recalc در `update_settings` |
| `tests/test_risk_module.py` | ۵ تست جدید: اجباری‌بودن exclusion_reason (رد/قبول)، صعودی‌بودن threshold (رد/قبول)، ویرایش‌پذیری criticality_score |

هیچ Migration جدیدی لازم نبود (تنظیمات ردیف‌داده هستند، نه ستون). Seed مجدداً
اجرا و ۸ ردیف جدید درج شد.

---

## چک‌لیست معیار پذیرش نهایی (بر اساس Phaseها)

| Phase | موضوع | وضعیت |
|-------|-------|-------|
| 0 | شناخت وضعیت فعلی | ✅ کامل — ماژول از قبل موجود و ۹۵٪ کامل بود |
| 1 | مدل‌های داده (۷ جدول با FK به `asset_inventory`) | ✅ همه فیلدها/Unique Index/Constraintها طبق مستند |
| 2 | Criticality (25/50/75/100، پیش‌فرض medium، Audit Log، `assigned_by/at/reason`) | ✅ + رفع نقص #1 (اکنون از Settings قابل‌ویرایش) |
| 3 | Zone (۶ سطح 20–100 + Unknown، CRUD، حذف مشروط، Recalc) | ✅ کامل |
| 4 | Open Ports (severity weight، فقط Open، factor=4، سقف 100، Closed خارج، exclusion) | ✅ + رفع نقص #2 (exclusion_reason اجباری) |
| 5 | Audit Risk (فرمول `100×Σfail/Σapplicable`، فقط Applicable در مخرج، Warning اختیاری، آخرین Audit) | ✅ تست فرمول با A=45 سبز |
| 6 | ارتباط Hardening↔Audit (Resolve فقط با verify موفق) | ✅ کامل، تست‌شده |
| 7 | فرمول نهایی `0.25C+0.20Z+0.15P+0.40A`، clamp، Risk Level، Edge caseها | ✅ تست 69.50/Very High سبز؛ همه fallbackها پیاده |
| 8 | سرویس محاسبه + همه Triggerها + Recalc All async | ✅ + رفع نقص #3 (Threshold تریگر Recalc) |
| 9 | APIها (همه Endpointهای مستند) | ✅ کامل، شامل `incomplete_data` filter و Export CSV/JSON |
| 10 | Permissions (RISK read/write/delete) و Audit Log | ✅ کامل |
| 11 | خروجی CSV/JSON، Pagination/Filter سمت سرور، Indexها | ✅ کامل |
| 12 | موارد خارج از محدوده | ✅ هیچ‌کدام پیاده نشده (بررسی شد) |

### تست‌های اجباری بخش ۳۰

| تست | وضعیت |
|-----|-------|
| Criticality 25/50/75/100 + Recalc | ✅ |
| Zone score + Recalc + عدم تخصیص Zone حذف‌شده | ✅ |
| Open Port: فقط Open، Excluded خارج، severity، سقف 100، Closed خارج | ✅ |
| Audit: فقط Applicable در مخرج، فقط Active در صورت، Pass/Resolved/NA خارج، تقسیم‌بر‌صفر | ✅ |
| Hardening: بدون verify رفع نمی‌شود، با verify رفع می‌شود، کاهش امتیاز | ✅ |
| Formula C=100,Z=80,P=70,A=45 → 69.50 | ✅ |
| Boundary 0/19.99/20/39.99/40/59.99/60/79.99/80/100 | ✅ |
| **جدید:** exclusion_reason اجباری | ✅ |
| **جدید:** threshold صعودی + criticality_score قابل‌ویرایش | ✅ |

**نتیجه اجرا:** `34 passed`

---

## تصمیم‌های فنی

1. **تطبیق با اسکیمای موجود (نه مستند خام):** `HardeningAction` ستون
   `verification_status` ندارد بلکه Boolean `verification_passed` دارد؛ قاعده‌ی
   Resolved = `action_type != preview` و `status == success` و
   `verification_passed is True`. `AuditResult.status` از نوع Enum `CheckStatus`
   است و `NOT_APPLICABLE`/`ERROR` از مخرج حذف می‌شوند. این تطبیق‌ها از قبل در
   ماژول موجود بودند و صحیح‌اند.

2. **تغییر criticality_score تریگر Recalc All نمی‌کند:** چون پروفایل هر دارایی
   امتیاز عددی خودش را ذخیره می‌کند (نگاشت سطح فقط هنگام ست‌کردن سطح جدید انجام
   می‌شود)، تغییر این تنظیم روی دارایی‌های موجود اثری ندارد و Recalc غیرضروری
   است. اما تغییر Threshold سطحِ همه دارایی‌ها را بدون تغییر امتیاز عوض می‌کند،
   پس این مورد به تریگر Recalc اضافه شد.

3. **Seed به‌جای Migration:** تنظیمات جدید ردیف‌داده هستند؛ با Seed idempotent
   اضافه شدند تا customization اپراتور حفظ شود.

---

## ریسک‌ها و موارد نیازمند تأیید کارفرما

1. **اجرای Seed در محیط‌های دیگر:** در هر محیط (staging/production) باید
   `python -m app.modules.risk.seed` با `DATABASE_URL` صحیح (dialect `+psycopg`)
   یک‌بار اجرا شود تا ۸ تنظیم جدید درج و از UI قابل‌ویرایش شوند. در محیط توسعه‌ی
   فعلی اجرا و تأیید شد.

2. **مقیاس‌پذیری Recalculate All:** پیاده‌سازی async و per-asset try/except است و
   از نظر Query/Index برای مقیاس مستند طراحی شده، اما بار واقعی
   (۱۰۰۰ دارایی / ۱۰۰٬۰۰۰ پورت / ۱٬۰۰۰٬۰۰۰ finding) در این ممیزی اجرا نشد؛
   در صورت نیاز تست بار جداگانه توصیه می‌شود.

3. **`datetime.utcnow()` منسوخ:** در کل کد (نه فقط این ماژول) استفاده شده و
   Warning تولید می‌کند؛ خارج از محدوده‌ی این ممیزی و نیازمند تصمیم پروژه‌ای.
