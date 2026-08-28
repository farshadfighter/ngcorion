# راهنمای فنی ماژول Risk (ریسک و اکسپوژر)

هدف این سند این است که یک توسعه‌دهنده‌ی جدید در کمتر از ۱۰ دقیقه معماری ماژول
ریسک را بفهمد. کد اصلی در `app/modules/risk/` و مدل‌ها در `app/models/risk.py`
قرار دارند.

---

## ۱) معماری کلی — شش مؤلفه و فرمول

هر دارایی (Asset) یک **امتیاز ریسک ۰ تا ۱۰۰** می‌گیرد که از ترکیب وزن‌دار
شش مؤلفه‌ی مشخص‌شده در NGCorion Risk Score Calculation Specification ساخته
می‌شود:

| مؤلفه | منبع داده | معنی | وزن |
|-------|-----------|------|----:|
| **AC — Criticality** (بحرانیت) | `asset_risk_profiles` | اهمیت کسب‌وکاری دارایی (low/medium/high/critical) | ۲۰٪ |
| **AR — Asset Risk** (ریسک ذاتی دارایی) | `asset_inventory.risk_level` | سطح ریسک خودِ دارایی، مستقل از ممیزی/هاردنینگ | ۲۰٪ |
| **AZ — Zone** (منطقه‌ی شبکه) | `risk_zones` | میزان در معرض بودن شبکه (DMZ، اینترنت‌فیسینگ، داخلی و…) | ۱۵٪ |
| **OP — Open Ports** (پورت‌های باز) | `asset_open_ports` | اکسپوژر ناشی از پورت‌های باز، وزن‌دهی‌شده با ریسک سرویس | ۱۰٪ |
| **AF — Audit Failure** (یافته‌های ممیزی) | `audit_sessions` / `audit_results` | درصد وزنی کنترل‌های مردود از کل کنترل‌های قابل‌اجرا (بدون کسر هاردنینگ) | ۲۵٪ |
| **HF — Hardening Fix Found** (فیکس‌های شناسایی‌شده) | `hardening_actions` | درصد وزنی یافته‌های مردودی که برایشان فیکس شناسایی شده | ۱۰٪ |

**فرمول نهایی** (در `service.py`، STEP 8):

```
contribution(x)  = score(x) * weight(x) / 100
final_risk_score = Σ contribution(criticality, asset_risk, zone, open_port, audit, hardening)
final_risk_score = min(100, max(0, round(final_risk_score)))
```

شش وزن باید همیشه جمعشان **۱۰۰** شود (در endpoint تنظیمات اعتبارسنجی می‌شود).
سپس امتیاز نهایی با آستانه‌ها به یک **سطح ریسک** نگاشت می‌شود (پنج سطح، مطابق
بخش ۱۰ اسپک، با کران‌های شکاف‌دار):
`informational (۰-۲۰) → low (۲۱-۴۰) → medium (۴۱-۶۰) → high (۶۱-۸۰) → critical (۸۱-۱۰۰)`.

---

## ۲) جداول دیتابیس (`app/models/risk.py`)

| جدول | توضیح یک‌خطی |
|------|-------------|
| `risk_settings` | همه‌ی تنظیمات موتور (وزن‌ها، شدت‌ها، آستانه‌ها) به‌صورت key/value تایپ‌دار |
| `risk_zones` | تعریف مناطق شبکه و امتیاز اکسپوژر هرکدام (۰ تا ۱۰۰) |
| `asset_risk_profiles` | ورودی‌های هر دارایی: سطح بحرانیت و منطقه‌ی اختصاص‌یافته (یک ردیف per asset) |
| `asset_open_ports` | پورت‌های باز مشاهده‌شده‌ی هر دارایی با شدت و پرچم شمول در ریسک |
| `asset_risk_scores` | آخرین امتیاز محاسبه‌شده‌ی هر دارایی (یک ردیف per asset، upsert می‌شود) |
| `asset_risk_history` | سری‌زمانی امتیازها؛ در هر محاسبه یک ردیف جدید ثبت می‌شود |
| `risk_calculation_logs` | لاگ هر اجرای محاسبه برای دیباگ و ردیابی (ورودی/خروجی/خطا/تریگر) |

---

## ۳) سرویس محاسبه — گام‌به‌گام (`service.py::calculate`)

سرویس `AssetRiskCalculationService.calculate(asset_id, db, trigger_type, …)`
برای یک دارایی این مراحل را طی می‌کند:

1. **STEP 1 — بارگذاری تنظیمات:** ردیف‌های `risk_settings` روی `DEFAULT_SETTINGS` مرج می‌شوند (اگر ردیفی نبود، مقدار پیش‌فرض کد استفاده می‌شود).
2. **STEP 3 — پروفایل:** اگر پروفایل دارایی نبود، با پیش‌فرض `medium` ساخته و «داده ناقص» علامت می‌خورد.
3. **STEP 4 — Criticality:** امتیاز بحرانیت از `criticality_score` پروفایل یا نگاشت سطح.
4. **STEP 5 — Zone:** امتیاز منطقه؛ اگر منطقه‌ای ست نشده، `unknown_zone_score` و علامت ناقص.
5. **STEP 6 — Open Ports:** جمع وزن شدت پورت‌های باز و شامل‌شده، نرمال‌سازی با `open_port_normalization_factor` و سقف ۱۰۰.
6. **STEP 7 — Audit:** آخرین AuditSession معتبر (غیر running) خوانده می‌شود؛ برای هر کنترل مردود، اگر **هاردنینگ موفق و verify‌شده** داشته باشد از شمار فعال کسر (resolved) وگرنه در `failed_weight` جمع می‌شود. امتیاز = `100 * failed_weight / applicable_weight`.
7. **STEP 8 — ترکیب وزن‌دار:** contribution هر مؤلفه محاسبه و جمع می‌شود.
8. **STEP 9 — سطح ریسک:** با آستانه‌ها از بالا به پایین تعیین می‌شود.
9. **STEP 10 — ذخیره:** ردیف `asset_risk_scores` آپسرت، یک ردیف `asset_risk_history` و یک `risk_calculation_logs` درج، و در صورت تغییر سطح یک audit-log ثبت می‌شود.

> نکته: امتیاز audit یک finding را «حل‌شده» می‌شمارد تنها وقتی
> `action_type != "preview"` و `status == "success"` و `verification_passed is True`.
> این همان قاعده‌ای است که endpoint یافته‌ها (بخش ۵) هم به کار می‌برد.

---

## ۴) Triggerها — چه رویدادهایی محاسبه‌ی مجدد را راه می‌اندازند

هر تریگر با یک `trigger_type` ثبت می‌شود (در history/log دیده می‌شود):

| trigger_type | چه زمانی |
|--------------|----------|
| `manual` | فراخوانی دستی `POST /assets/{id}/calculate` |
| `profile_updated` | تغییر بحرانیت یا منطقه‌ی دارایی |
| `zone_updated` | تغییر امتیاز یک زون → همه‌ی دارایی‌های آن زون (پس‌زمینه) |
| `port_updated` | ویرایش یک پورت (شدت/شمول در ریسک) |
| `port_scan_updated` | ورود نتایج اسکن پورت جدید |
| `asset_created` | ساخته‌شدن دارایی |
| `audit_completed` | اتمام یک ممیزی CIS (سرویس‌های audit هر وندور) |
| `hardening_verified` | موفق و verify‌شدن یک اکشن هاردنینگ |
| `settings_changed` / `bulk_recalculation` | تغییر وزن‌ها/نرمال‌سازی یا `POST /recalculate-all` (همه‌ی دارایی‌ها، پس‌زمینه) |

ماژول‌های audit و hardening هر وندور (cisco/fortinet/linux/…) پس از کار خود
سرویس ریسک را صدا می‌زنند، پس امتیازها همیشه به‌روز می‌مانند.

---

## ۵) APIها (`router.py`، پیشوند `/api/risk`)

دسترسی‌ها با `require_permission("RISK", …)`: خواندن/خروجی = `read`،
محاسبه/ویرایش = `write`، حذف زون = `delete`.

| Endpoint | توضیح |
|----------|-------|
| `GET /summary` | متریک‌های تجمیعی داشبورد (تعداد، میانگین، شکست بر حسب سطح/زون/محرمانگی) |
| `GET /trend?months=` | میانگین ماهانه‌ی امتیاز در N ماه اخیر |
| `GET /assets` | رتبه‌بندی صفحه‌بندی‌شده و فیلترپذیر دارایی‌ها |
| `GET /assets/{id}` | جزئیات کامل ریسک یک دارایی (+ `hardening_impact`، پورت‌ها، خلاصه‌ی ممیزی، history) |
| `GET /assets/{id}/findings` | یافته‌های مردود آخرین ممیزی + وضعیت هاردنینگ/حل‌شدگی هر کنترل |
| `POST /assets/{id}/calculate` | محاسبه‌ی فوری ریسک یک دارایی |
| `POST /recalculate-all` | محاسبه‌ی همه‌ی دارایی‌ها در پس‌زمینه |
| `GET/PUT /assets/{id}/profile` | مشاهده/ویرایش بحرانیت و زون دارایی |
| `GET /zones`، `POST /zones`، `PUT /zones/{id}`، `DELETE /zones/{id}` | مدیریت زون‌ها |
| `GET /assets/{id}/ports`، `PUT /ports/{id}` | مشاهده/ویرایش پورت‌های باز |
| `GET/PUT /settings` | مشاهده/ویرایش تنظیمات موتور ریسک |
| `GET /assets/{id}/history` | تاریخچه‌ی امتیاز یک دارایی |
| `GET /export/csv`، `GET /assets/{id}/export/json` | خروجی CSV کل و JSON یک دارایی |

**داشبورد هاردنینگ** (`app/modules/hardening/dashboard_router.py`، پیشوند
`/api/hardening/dashboard`، دسترسی `HARDENING read`):

| Endpoint | توضیح |
|----------|-------|
| `GET /assets-requiring-hardening` | دارایی‌هایی که `active_audit_findings_count > 0` دارند، مرتب بر اساس امتیاز ریسک، همراه با تعداد حل‌شده با هاردنینگ و تاریخ آخرین هاردنینگ |

### بلوک `hardening_impact` در جزئیات دارایی
در پاسخ `GET /assets/{id}` یک بلوک `hardening_impact` هست که ریسک **قبل از اولین
هاردنینگ** (baseline: آخرین ردیف history پیش از اولین `executed_at`) را با ریسک
فعلی مقایسه می‌کند و `reduction` و `reduction_percent` را برمی‌گرداند.

---

## ۶) Edge caseها — رفتار با داده‌ی ناقص

- **نبود پروفایل/زون/اسکن/ممیزی:** به‌جای شکست، از مقدار fallback
  (`unknown_*_score`) استفاده و دارایی با `incomplete_data=true` و دلایل در
  `incomplete_reasons` علامت‌گذاری می‌شود.
- **ممیزی بدون کنترل applicable:** امتیاز audit = `unknown_audit_score`.
- **`hardening_impact` بدون هیچ هاردنینگ:** همه‌ی فیلدها `null`.
- **`hardening_impact` بدون history پیش از اولین هاردنینگ:** فیلدهای baseline `null`.
- **تقسیم بر صفر:** اگر `baseline_score == 0` باشد، `reduction_percent = null`.
- **`findings` بدون ممیزی معتبر:** `{"audit_session_id": null, "findings": []}`.
- **finding بدون اکشن هاردنینگ:** با LEFT JOIN همچنان برگردانده می‌شود و
  فیلدهای هاردنینگ `null`، `is_resolved=false`.
- **دارایی هرگز محاسبه‌نشده:** `risk_score = null` و `incomplete_reasons = ["not_calculated"]`.

---

## ۷) تنظیمات قابل‌تغییر (`risk_settings`)

از طریق `PUT /api/risk/settings` (فقط ردیف‌های `is_editable`). مهم‌ترین‌ها:

- **وزن مؤلفه‌ها** (باید جمعشان ۱۰۰ شود): `criticality_weight`، `asset_risk_weight`،
  `zone_weight`، `open_port_weight`، `audit_weight`، `hardening_weight`.
- **وزن شدت یافته‌ها (AF/HF):** `severity_{low,medium,high,critical}_weight`.
- **وزن شدت پورت (OP):** `port_severity_{low,medium,high,critical}_weight`.
- **امتیاز بحرانیت (AC):** `criticality_{low,medium,high,critical}_score`.
- **امتیاز ریسک دارایی (AR):** `asset_risk_{low,medium,high,critical}_score`
  (اسپک دقیقاً چهار سطح دارد؛ مقدار قدیمیِ `very_high` روی
  `asset_inventory.risk_level` مثل نامشخص‌بودن مقدار امتیازدهی می‌شود).
- **نرمال‌سازی پورت:** `open_port_normalization_factor`.
- **مقادیر fallback:** `unknown_{zone,port,audit,asset_risk}_score`،
  `no_hardening_data_score`.
- **آستانه‌های سطح:** `risk_level_{low,medium,high,critical}_threshold`
  (کران پایین *شامل* همان سطح؛ `informational` کف است و کلید ندارد).
- **رفتار:** `include_warning_in_audit_risk`.

> تغییر هر تنظیمی که `weight` یا `normalization` در نامش باشد، به‌طور خودکار
> محاسبه‌ی مجدد همه‌ی دارایی‌ها را در پس‌زمینه راه می‌اندازد.
