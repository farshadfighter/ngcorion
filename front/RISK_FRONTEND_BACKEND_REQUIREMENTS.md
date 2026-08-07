# Risk Intelligence — نیازمندی‌های فرانت‌اند از بک‌اند

**تاریخ:** ۱۴۰۵/۰۵/۱۵ (2026-08-06)
**موضوع:** صفحه‌ی «Risk Asset» طبق طراحی فیگما
**وضعیت فعلی بک‌اند:** ماژول risk پیاده‌سازی شده (`app/modules/risk/`) — ۱۶ endpoint، موتور محاسبه، ۶ جدول

---

## خلاصه‌ی مدیریتی

طراحی فیگمای صفحه‌ی Risk Asset شامل **۹ کارت KPI**، **۴ چارت** و **یک جدول Top 10** است.
از این میان:

- **جدول Top 10** با endpoint موجود کاملاً قابل پیاده‌سازی است (به‌جز یک ستون)
- **بقیه‌ی اجزا** یا endpoint ندارند یا فیلد لازم را برنمی‌گردانند

مهم‌ترین مسئله: **هیچ endpoint تجمیعی (aggregate/summary) وجود ندارد.**
تنها راه فعلی این است که فرانت کل لیست asset‌ها را با صفحه‌بندی بگیرد و سمت کلاینت
محاسبه کند. با توجه به سقف `page_size ≤ 100` این یعنی برای ۱۰۰۰ asset، ۱۰ درخواست
پشت‌سرهم — کند، شکننده، و با هر بار رفرش تکرار می‌شود.

**درخواست اصلی: یک endpoint تجمیعی `GET /api/risk/summary` اضافه شود.**

---

## بخش ۱ — مشکلات به تفکیک

### مشکل ۱ (بحرانی): سطوح ریسک بین بک‌اند و طراحی یکی نیست

**وضعیت فعلی کد:**
`app/modules/risk/service.py` خط ۲۲۹ تابع `_risk_level` **۵ سطح** برمی‌گرداند:

```python
critical    (>= 80)
very_high   (>= 60)
high        (>= 40)
medium      (>= 20)
low         (< 20)
```

اما `app/models/enums.py` خط ۱۵ کلاس `RiskLevelEnum` فقط **۴ سطح** دارد:

```python
LOW / MEDIUM / HIGH / CRITICAL
```

یعنی مقدار `very_high` که سرویس تولید می‌کند، در enum مدل وجود ندارد.

**تأثیر روی فرانت:**
چارت «Asset by Risk level» در فیگما ۴ بخش دارد، ولی API ممکن است ۵ مقدار مختلف
برگرداند. کارت‌های KPI هم جداگانه «Critical Risk assets»، «Very High Risk assets» و
«High Risk assets» دارند — که با ۴ سطحی بودن enum نمی‌خواند.

**سؤال از تیم بک‌اند:**
کدام یک درست است؟

- الف) `very_high` سطح رسمی است → لطفاً به `RiskLevelEnum` اضافه شود
- ب) `very_high` اشتباه است → از `_risk_level` حذف شود و آستانه‌ها بازتعریف شوند

**تصمیم موقت فرانت:** تا اعلام نظر شما، `very_high` را به‌عنوان سطح مستقل با رنگ
اختصاصی نمایش می‌دهیم (donut پنج‌بخشی).

---

### مشکل ۲ (بحرانی): endpoint تجمیعی وجود ندارد

**وضعیت فعلی:**
هیچ endpointی برای آمار کلی نیست. `GET /api/risk/assets` فقط لیست صفحه‌بندی‌شده
می‌دهد با سقف `page_size = 100` (خط ۳۳۹ روتر).

**اجزای فیگما که به این نیاز دارند:**

۹ کارت KPI:
| کارت | منبع داده |
|---|---|
| Number of assets | تعداد کل |
| Critical Risk assets | شمارش بر اساس `risk_level` |
| Very High Risk assets | شمارش بر اساس `risk_level` |
| High Risk assets | شمارش بر اساس `risk_level` |
| Risk Score average | میانگین `final_risk_score` |
| Number of incomplete assets | شمارش `incomplete_data = true` |
| Number of Open Ports | مجموع `open_ports_count` |
| Non-conformity asset | **تعریف نشده — بخش ۳ را ببینید** |
| Number of fixed section by hardening | مجموع `resolved_by_hardening_count` |

۴ چارت:
- Asset by Risk level (شمارش گروهی)
- Asset by Zone (شمارش گروهی)
- Asset by Confidentiality level (**فیلد موجود نیست — مشکل ۳**)
- Average Risk Score Trend (**داده موجود نیست — مشکل ۵**)

**راه‌حل پیشنهادی:**

```
GET /api/risk/summary
دسترسی: RISK read
```

پاسخ پیشنهادی:

```json
{
  "totals": {
    "total_assets": 98,
    "risk_score_average": 70.4,
    "incomplete_assets": 84,
    "open_ports_total": 10,
    "non_conformity_assets": 10,
    "fixed_by_hardening_total": 10
  },
  "by_risk_level": [
    { "level": "low",       "count": 20 },
    { "level": "medium",    "count": 8  },
    { "level": "high",      "count": 10 },
    { "level": "very_high", "count": 5  },
    { "level": "critical",  "count": 12 }
  ],
  "by_zone": [
    { "zone_id": 1, "zone_name": "DMZ", "count": 2 }
  ],
  "by_confidentiality": [
    { "level": "public",       "count": 5  },
    { "level": "internal",     "count": 16 },
    { "level": "confidential", "count": 10 },
    { "level": "critical",     "count": 20 }
  ]
}
```

**چرا این بهتر است:** یک کوئری `GROUP BY` سمت دیتابیس به‌جای ۱۰+ درخواست HTTP و
محاسبه‌ی سمت مرورگر. ضمناً آمار روی **کل** داده درست است، نه فقط صفحه‌ی جاری.

---

### مشکل ۳: تعریف «Non-conformity asset» مشخص نیست

در فیگما کارتی با عنوان **«Non-conformity asset»** وجود دارد، اما در کل ماژول risk
هیچ فیلد یا مفهومی با این نام پیدا نشد.

**حدس ما:** احتمالاً منظور asset‌هایی است که در آخرین audit، finding فعال دارند
(یعنی `active_audit_findings_count > 0`). این عدد در `AssetRiskScore` موجود است.

**درخواست:** لطفاً تعریف دقیق را مشخص کنید تا در `summary` گنجانده شود.
اگر حدس ما درست است، فیلد `non_conformity_assets` = تعداد asset‌هایی با
`active_audit_findings_count > 0`.

---

### مشکل ۴: دو فیلد لازم در لیست asset برنمی‌گردند

تابع `_list_item` (روتر خط ۲۷۴) این فیلدها را برمی‌گرداند:
`rank, asset_id, asset_name, hostname, ip_address, vendor, product, model,
os_version, criticality_level, zone_name, open_ports_count, final_risk_score,
risk_level, incomplete_data, calculated_at` و چند مورد دیگر.

**سه گروه فیلدی که کم است:**

**الف) `confidentiality_level`**
- در مدل `Asset` وجود دارد (`app/models/asset.py` خط ۱۷۶، از نوع `ConfidentialityLevelEnum`)
- ولی هیچ endpoint ریسکی آن را برنمی‌گرداند
- **لازم برای:** چارت «Asset by Confidentiality level» **و** ستون
  «Confidentiality Level» در جدول تب Overview — یعنی در دو جای مختلف

**ب) `asset_type` (ستون Type در جدول)**
- در جدول فیگما ستونی به نام **Type** با مقادیری مثل `Server` و `VM` هست
- مدل `Asset` فیلد `asset_type_id` دارد که FK به جدول `asset_types` است
  (`app/models/asset_types.py`، فیلد `type_name`)
- در حال حاضر `_list_item` فیلدی به نام `product` برمی‌گرداند که در واقع
  `asset.os_name` است — این همان Type نیست
- **لازم برای:** ستون Type در جدول Top 10

**ج) شمارش findings به تفکیک severity — برای تب «Audit Risk»**

طراحی فیگما یک تب دوم به نام **Audit Risk** دارد با این ستون‌ها:
`Critical Findings`, `High Findings`, `Medium Findings`, `Low Findings`.

این چهار مقدار **در مدل موجودند** و در `_score_to_dict` (روتر خط ۱۰۵ تا ۱۰۸)
هم برگردانده می‌شوند، ولی **در `_list_item` نیستند**. یعنی برای ساخت این تب،
فرانت مجبور است برای هر ردیف یک درخواست جدا به
`GET /api/risk/assets/{id}` بزند — برای ۱۰۰ asset یعنی ۱۰۰ درخواست.

**راه‌حل پیشنهادی:** هر سه گروه به `_list_item` اضافه شوند:

```python
"confidentiality_level": asset.confidentiality_level.value
                          if asset.confidentiality_level else None,
"asset_type": asset.asset_type.type_name if asset.asset_type else None,
"critical_findings_count": score.critical_findings_count,
"high_findings_count": score.high_findings_count,
"medium_findings_count": score.medium_findings_count,
"low_findings_count": score.low_findings_count,
```

هر شش فیلد از داده‌ای می‌آیند که کوئری همین حالا هم لود کرده است، پس هزینه‌ی
اضافه‌ای ندارد.

---

### مشکل ۵: داده‌ی روند زمانی تجمیعی وجود ندارد

چارت **«Average Risk Score Trend»** در فیگما ۱۲ ستون ماهانه دارد
(میانگین امتیاز ریسک کل سازمان در هر ماه).

**وضعیت فعلی:**
- جدول `asset_risk_history` وجود دارد و رکوردهای زمانی را نگه می‌دارد ✅
- ولی endpoint `GET /api/risk/assets/{asset_id}/history` فقط **برای یک asset** است
- هیچ endpointی میانگین کل سازمان در طول زمان نمی‌دهد

**راه‌حل پیشنهادی:**

```
GET /api/risk/trend?months=12
دسترسی: RISK read
```

```json
{
  "points": [
    { "period": "2025-09", "average_score": 71.0, "asset_count": 95 },
    { "period": "2025-10", "average_score": 77.0, "asset_count": 96 }
  ]
}
```

پیاده‌سازی: `GROUP BY` روی ماهِ `asset_risk_history.calculated_at` با
`AVG(risk_score)`.

---

### مشکل ۶: صفحه‌ی جزئیات asset — سه کمبود

با کلیک روی هر ردیف جدول، صفحه‌ی «Asset Risk» باز می‌شود
(`GET /api/risk/assets/{id}`). این endpoint **بیشتر صفحه را پوشش می‌دهد**:
کارت‌های بالا، Confidentiality & Zone، جدول Open Ports و کل بخش Audit Summary
از همین یک پاسخ ساخته می‌شوند. سه کمبود باقی می‌ماند:

**الف) دو ستون در جدول «Audit Findings»**

خودِ لیست findingها از `GET /api/audit/sessions/{session_id}/results` می‌آید
(با `audit_id` که در پاسخ ریسک هست زنجیر می‌شود) و هفت ستون از نه ستون را
پوشش می‌دهد. دو ستون باقی‌مانده هیچ منبعی ندارند:

- `Hardening Status`
- `Verification Status`

این داده **در دیتابیس هست**: `HardeningAction` فیلدهای `status` و
`verification_passed` را دارد و `service.py` (خط ۱۹۳ تا ۲۰۴) همین حالا برای
تشخیص «resolved» از آن استفاده می‌کند — ولی نتیجه‌اش فقط به‌صورت **شمارش**
ذخیره می‌شود، نه per-finding.

**راه‌حل پیشنهادی:** دو فیلد به پاسخ
`GET /api/audit/sessions/{id}/results` اضافه شود:

```python
"hardening_status": action.status if action else None,
"verification_status": (
    "passed" if action and action.verification_passed
    else "failed" if action else None
),
```

**نکته‌ی دسترسی:** این endpoint با `AUDITING` read محافظت می‌شود، ولی صفحه با
`RISK` read باز می‌شود. کاربری که فقط دسترسی ریسک دارد، ۴۰۳ می‌گیرد. فرانت این
حالت را با پیام مدیریت می‌کند، ولی اگر ترجیح می‌دهید داده‌ی findings از خود
ماژول ریسک بیاید (مثلاً `GET /api/risk/assets/{id}/findings` با دسترسی
`RISK` read)، بفرمایید تا فرانت را به آن وصل کنیم.

**ب) بخش «Hardening Impact» — مقادیر «قبل از hardening»**

این بخش سه مقایسه‌ی قبل/بعد می‌خواهد:

| مقدار فعلی | موجود؟ | مقدار «قبل» | موجود؟ |
|---|---|---|---|
| Number of Fixed Findings | ✅ `resolved_by_hardening_count` | Number of Findings prior to Hardening | ❌ |
| Current Audit Risk | ✅ `audit_risk_score` | Audit Risk Prior to Hardening | ❌ |
| Current Risk Score | ✅ `final_risk_score` | Risk Score Before Hardening | ❌ |

جدول `asset_risk_history` رکوردهای زمانی را نگه می‌دارد و ستون `reason` هم
دارد، ولی هیچ مقدار مشخصی نشان نمی‌دهد کدام رکورد «بلافاصله پیش از hardening»
بوده است. بدون آن، سه ستون سمت راست و هر سه progress bar قابل محاسبه نیستند.

**راه‌حل پیشنهادی (دو گزینه):**

۱. در پاسخ جزئیات یک بلوک `hardening_impact` اضافه شود که بک‌اند خودش
   baseline را پیدا کرده باشد:

```json
"hardening_impact": {
  "findings_before": 56,
  "findings_fixed": 10,
  "audit_risk_before": 72.0,
  "audit_risk_current": 51.0,
  "risk_score_before": 97.0,
  "risk_score_current": 90.0
}
```

۲. یا ساده‌تر: تضمین شود که هنگام اجرای hardening یک رکورد در
   `asset_risk_history` با `reason` مشخص (مثلاً `"pre_hardening"`) نوشته
   می‌شود، تا فرانت خودش آخرین رکورد قبل از آن را بردارد.

گزینه‌ی ۱ ترجیح ماست چون منطق را در یک جا نگه می‌دارد.

**ج) `confidentiality_level` — سومین جایی که لازم است**

ستون «Confidentiality» در بخش Confidentiality & Zone همین صفحه هم به این فیلد
نیاز دارد. با مشکل ۴ (بند الف) یکی است و با همان تغییر حل می‌شود.

**نکته‌ی طراحی (خارج از کمبود بک‌اند):** بخش Confidentiality & Zone در فیگما
آیکون ویرایش دارد. `PUT /api/risk/assets/{id}/profile` فقط `criticality_level`
و `zone_id` می‌گیرد — یعنی confidentiality از این مسیر قابل ویرایش نیست
(احتمالاً باید از ماژول assets ویرایش شود). فعلاً دکمه‌های ویرایش غیرفعال
گذاشته شده‌اند تا تکلیفش روشن شود.

---

## بخش ۲ — جمع‌بندی درخواست‌ها

به ترتیب اولویت:

| # | درخواست | نوع | بدون آن چه می‌شود |
|---|---|---|---|
| ۱ | تعیین تکلیف `very_high` | تصمیم | چارت و کارت‌های KPI ممکن است غلط دسته‌بندی کنند |
| ۲ | `GET /api/risk/summary` | endpoint جدید | ۹ کارت KPI و ۳ چارت پیاده نمی‌شوند (یا با ۱۰+ request کند) |
| ۳ | تعریف «Non-conformity asset» | تصمیم | یک کارت KPI خالی می‌ماند |
| ۴ | افزودن ۶ فیلد به `_list_item` (بخش ۱، مشکل ۴) | تغییر کوچک | یک چارت، سه ستون جدول، و کل تب «Audit Risk» ناقص می‌مانند |
| ۵ | `GET /api/risk/trend` | endpoint جدید | چارت روند خالی می‌ماند |
| ۶ | بلوک `hardening_impact` در پاسخ جزئیات (مشکل ۶ب) | endpoint موجود، فیلد جدید | نیمی از بخش «Hardening Impact» خالی می‌ماند |
| ۷ | دو فیلد وضعیت hardening در نتایج audit (مشکل ۶ الف) | تغییر کوچک | دو ستون جدول Audit Findings خالی می‌ماند |
| ۸ | تصمیم درباره‌ی دسترسی findings (مشکل ۶ الف، نکته) | تصمیم | کاربر بدون دسترسی Auditing، جدول findings را نمی‌بیند |

---

## بخش ۳ — نکات عملیاتی (خارج از فیگما، ولی مهم)

این دو مورد در بررسی کد پیدا شد و روی نمایش داده اثر مستقیم دارد:

**الف) seed خودکار اجرا نمی‌شود**
تابع `seed_risk_defaults` در `app/modules/risk/seed.py` نوشته شده اما از startup
اپلیکیشن صدا زده نمی‌شود. روی دیتابیس تازه، جدول‌های `risk_settings` و `risk_zones`
خالی می‌مانند — یعنی چارت «Asset by Zone» خالی و وزن‌ها روی مقادیر fallback.

اجرای دستی: `python -m app.modules.risk.seed`

**پیشنهاد:** در startup صدا زده شود (idempotent است و رکوردهای موجود را دست نمی‌زند).

**ب) جدول `asset_open_ports` هیچ نویسنده‌ای ندارد**
در کل کدبیس فقط از این جدول **خوانده** می‌شود؛ هیچ کدی در آن رکورد **نمی‌نویسد**.
یعنی ماژول discovery هنوز به risk وصل نشده.

نتیجه: فاکتور open-port برای همه‌ی asset‌ها مقدار fallback (۵۰) می‌گیرد و
`incomplete_data` روی `true` می‌ماند. کارت «Number of Open Ports» عملاً همیشه صفر
خواهد بود.

**سؤال:** آیا اتصال discovery → asset_open_ports در برنامه هست؟

---

## بخش ۴ — وضعیت فعلی فرانت

سه صفحه ساخته شده است. هرجا داده‌ای نیست، به‌جای صفر یا مقدار ساختگی، یک خط
تیره‌ی کم‌رنگ یا پیام صریح نمایش داده می‌شود.

**۱. Risk Intelligence** (`/risk/overview`)

| بخش | وضعیت |
|---|---|
| ۹ کارت KPI | ⏳ محاسبه‌ی موقت کلاینت‌ساید؛ «fixed by hardening» خالی |
| چارت Risk level | ✅ |
| چارت Zone | ✅ |
| چارت Confidentiality | ⏳ منتظر مشکل ۴ |
| چارت Trend | ⏳ منتظر مشکل ۵ |
| جدول Top 10 | ✅ به‌جز ستون Type (مشکل ۴ب) |

**۲. Risk Asset** (`/risk/assets`)

| بخش | وضعیت |
|---|---|
| تب Overview | ✅ به‌جز ستون Confidentiality |
| تب Audit Risk | ⏳ چهار ستون Findings خالی (مشکل ۴ج) |
| سرچ | ✅ فعلاً کلاینت‌ساید |

**۳. Asset Risk Detail** (`/risk/assets/{id}`)

| بخش | وضعیت |
|---|---|
| ۴ کارت بالا | ✅ |
| Confidentiality & Zone | ✅ به‌جز مقدار confidentiality |
| Open Ports | ✅ کامل |
| Audit Summary (۱۲ ردیف) | ✅ کامل |
| Audit Findings | ✅ ۷ ستون از ۹ (مشکل ۶ الف) |
| Hardening Impact | ⏳ ستون «قبل» خالی (مشکل ۶ب) |

پس از افزوده شدن `/summary` و `/trend`، محاسبات موقت کلاینت‌ساید حذف و به API
منتقل می‌شوند.

---

**تماس:** در صورت نیاز به توضیح بیشتر یا هماهنگی درباره‌ی شکل دقیق پاسخ‌ها، در
خدمتیم. شکل JSON پیشنهادی بالا صرفاً پیشنهاد است — هر ساختاری که برایتان
راحت‌تر است، فرانت خود را با آن تطبیق می‌دهد.
