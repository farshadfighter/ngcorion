# مستندات کامل API - کشف خودکار دارایی‌ها (Asset Auto Discovery)

---

## **مسیر پایه:** `/api/discovery`

---

## **۱. اندپوینت‌های مدیریت اسکن**

### **POST `/api/discovery/scan`** - شروع اسکن جدید شبکه
**هدف:** راه‌اندازی اسکن شبکه برای کشف هاست‌ها و سرویس‌ها

**بدنه درخواست:**
```json
{
  "job_name": "نام اختیاری اسکن",
  "target": "192.168.1.0/24",
  "scan_type": "well_known_ports",
  "ports": "80,443",
  "protocol": "TCP"
}
```

**پارامترها:**
- `job_name` (اختیاری): در صورت عدم ارسال، به صورت خودکار تولید می‌شود (فرمت: `Scan-XX-IP`)
- `target`: آی‌پی/CIDR/محدوده (مثال: `192.168.1.1`، `192.168.1.0/24`، `192.168.1.1-254`)
- `scan_type`:
  - `all_ports`: اسکن تمام ۶۵۵۳۵ پورت (کندترین، کامل‌ترین)
  - `well_known_ports`: پورت‌های ۱ تا ۱۰۲۴ (پیش‌فرض، متعادل)
  - `custom_ports`: پورت‌های خاص (نیاز به پارامتر `ports` دارد)
- `ports`: مشخصات پورت (مثال: `80`، `80,443`، `1-1000`)
- `protocol`: `TCP`، `UDP`، یا `BOTH`

**پاسخ:** شیء اسکن با `scan_id` برای نظرسنجی (polling)

**مجوز:** دسترسی نوشتن (write)

---

### **GET `/api/discovery/scan/{scan_id}`** - دریافت وضعیت اسکن
**هدف:** نظرسنجی این اندپوینت برای بررسی پیشرفت اسکن و دریافت نتایج

**زمان استفاده:** هر ۳ ثانیه یک بار در حین اجرای اسکن

**مقادیر وضعیت پاسخ:**
- `running`: اسکن در حال اجراست
- `completed`: اسکن به پایان رسید، هاست‌ها در دسترس هستند
- `failed`: خطا در اسکن رخ داده است

**برمی‌گرداند:** جزئیات اسکن + هاست‌های کشف شده هنگام تکمیل

**مجوز:** عمومی (برای کاربران احراز هویت شده)

---

### **GET `/api/discovery/scans`** - دریافت تمام اسکن‌های اخیر
**هدف:** دریافت ۲۰ اسکن آخر از تاریخچه

**برمی‌گرداند:** آرایه‌ای از اشیاء اسکن

**مجوز:** دسترسی خواندن (read)

---

### **DELETE `/api/discovery/scan/{scan_id}`** - حذف اسکن
**هدف:** حذف اسکن از تاریخچه

**مجوز:** دسترسی حذف (delete)

---

## **۲. اندپوینت‌های هاست‌های در انتظار**

### **GET `/api/discovery/pending`** - دریافت هاست‌های در انتظار
**هدف:** دریافت تمام هاست‌های کشف شده که منتظر تایید/رد هستند

**پارامترهای Query:**
- `scan_id` (اختیاری): فیلتر بر اساس اسکن خاص

**برمی‌گرداند:**
```json
{
  "total": 5,
  "pending": [
    {
      "id": 1,
      "scan_id": "ABC123",
      "ip_address": "192.168.1.10",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "hostname": "server-01",
      "os_info": "Linux 5.x",
      "os_accuracy": 95,
      "open_ports": [...],
      "status": "pending",
      "matched_asset_id": null,
      "discovered_at": "2025-12-11T10:30:00"
    }
  ]
}
```

**مهم:** فقط هاست‌هایی با `status="pending"` را نمایش می‌دهد. پس از تایید/ادغام/رد، از این لیست حذف می‌شوند.

**مجوز:** دسترسی خواندن (read)

---

### **GET `/api/discovery/hosts/{host_id}/check-matches`** - بررسی دارایی‌های منطبق
**هدف:** یافتن دارایی‌های موجود که ممکن است با یک هاست کشف شده مطابقت داشته باشند (استفاده توسط دکمه "بررسی و تایید")

**اولویت مطابقت:**
1. **آدرس IP** (بالاترین اطمینان)
2. **آدرس MAC** (اطمینان متوسط)
3. **نام هاست** (کمترین اطمینان)

**برمی‌گرداند:**
```json
{
  "host_id": 1,
  "discovered_host": {
    "ip_address": "192.168.1.10",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "hostname": "server-01"
  },
  "matches": [
    {
      "asset_id": 123,
      "asset_name": "سرور تولید",
      "match_type": "ip_address",
      "confidence": "high",
      "asset_type": "Server"
    }
  ],
  "match_count": 1
}
```

**مجوز:** دسترسی خواندن (read)

---

### **POST `/api/discovery/hosts/{host_id}/approve`** - تایید هاست کشف شده
**هدف:** اندپوینت اصلی برای پردازش هاست‌های کشف شده

**سه اکشن در دسترس:**

#### **اکشن ۱: `merge_with_existing`**
ادغام داده‌های کشف شده با دارایی موجود

**درخواست:**
```json
{
  "action": "merge_with_existing",
  "asset_id": 123
}
```

**رفتار:**
- فقط فیلدهای خالی در دارایی موجود را به‌روزرسانی می‌کند
- `matched_asset_id` را در هاست کشف شده تنظیم می‌کند
- وضعیت هاست را به `"merged"` تغییر می‌دهد
- لیست فیلدهای به‌روزرسانی شده را برمی‌گرداند

---

#### **اکشن ۲: `create_new`**
ایجاد دارایی جدید از هاست کشف شده

**درخواست:**
```json
{
  "action": "create_new",
  "asset_data": {
    "asset_name": "سرور جدید",
    "asset_type_id": 1
  }
}
```

**رفتار:**
- دارایی جدید با داده‌های کشف شده ایجاد می‌کند (IP، MAC، hostname، OS)
- `matched_asset_id` را به ID دارایی جدید تنظیم می‌کند
- وضعیت هاست را به `"approved"` تغییر می‌دهد
- ID دارایی جدید را برمی‌گرداند

---

#### **اکشن ۳: `skip`**
علامت‌گذاری به عنوان بررسی شده بدون ایجاد/ادغام

**درخواست:**
```json
{
  "action": "skip"
}
```

**رفتار:**
- وضعیت هاست را به `"skipped"` تغییر می‌دهد
- از لیست در انتظار حذف می‌شود
- هیچ ایجاد/تغییر دارایی صورت نمی‌گیرد

**مجوز:** دسترسی نوشتن (write)

---

### **POST `/api/discovery/hosts/{host_id}/reject`** - رد هاست کشف شده
**هدف:** رد یک هاست و حذف از لیست در انتظار

**رفتار:**
- وضعیت را به `"rejected"` تغییر می‌دهد
- از لیست در انتظار حذف می‌شود
- هیچ دارایی ایجاد نمی‌شود

**مجوز:** دسترسی نوشتن (write)

---

### **POST `/api/discovery/bulk-approve`** - تایید دسته‌جمعی چندین هاست
**هدف:** ایجاد دارایی برای چندین هاست به طور همزمان با مقادیر پیش‌فرض

**درخواست:**
```json
{
  "host_ids": [1, 2, 3],
  "default_asset_type_id": 1,
  "default_location_id": 5,
  "default_owner_id": 10
}
```

**رفتار:**
- دارایی برای تمام هاست‌های مشخص شده ایجاد می‌کند
- از hostname یا `Host-{IP}` به عنوان نام دارایی استفاده می‌کند
- یک نوع دارایی/مکان/مالک به همه اعمال می‌کند

**برمی‌گرداند:**
```json
{
  "approved": 3,
  "errors": null,
  "created_assets": [...]
}
```

**مجوز:** دسترسی نوشتن (write)

---

## **۳. اندپوینت‌های مطابقت دارایی**

### **GET `/api/discovery/match/{ip_address}`** - یافتن دارایی بر اساس IP
**هدف:** بررسی اینکه آیا IP قبلاً در لیست دارایی‌ها وجود دارد

**برمی‌گرداند:**
```json
{
  "found": true,
  "asset_id": 123,
  "asset_name": "Server-01",
  "empty_fields": ["hostname", "os_name"],
  "current_values": {
    "hostname": null,
    "mac_address": "AA:BB:CC:DD:EE:FF"
  }
}
```

**مورد استفاده:** تعیین اینکه آیا باید دارایی موجود را به‌روزرسانی کرد یا دارایی جدید ایجاد کرد

**مجوز:** عمومی (احراز هویت شده)

---

## **۴. اندپوینت‌های اعمال کشف**

### **POST `/api/discovery/apply`** - اعمال داده‌های کشف به دارایی
**هدف:** به‌روزرسانی دارایی موجود با داده‌های کشف شده

**درخواست:**
```json
{
  "asset_id": 123,
  "ip_address": "192.168.1.10",
  "fields_to_apply": ["hostname", "os_name", "mac_address"]
}
```

**پارامتر Query:** `scan_id` (الزامی)

**رفتار:**
- **فقط فیلدهای خالی را به‌روزرسانی می‌کند** (غیرمخرب)
- فیلدهای به‌روزرسانی شده را در JSON `discovered_fields` علامت‌گذاری می‌کند
- فیلدهایی که قبلاً مقدار دارند را نادیده می‌گیرد

**برمی‌گرداند:**
```json
{
  "asset_id": 123,
  "updated_fields": ["hostname", "os_name"],
  "skipped_fields": ["mac_address (قبلاً دارای داده است)"],
  "message": "۲ فیلد به‌روزرسانی شد، ۱ فیلد نادیده گرفته شد"
}
```

**مجوز:** دسترسی نوشتن (write)

---

### **POST `/api/discovery/create-asset`** - ایجاد دارایی از کشف
**هدف:** ایجاد دارایی جدید از داده‌های هاست کشف شده

**درخواست:**
```json
{
  "asset_name": "سرور تولید",
  "asset_type_id": 1,
  "discovered_host": {
    "ip_address": "192.168.1.10",
    "hostname": "server-01",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os_name": "Linux",
    "os_version": "5.x"
  }
}
```

**رفتار:**
- دارایی جدید با تمام داده‌های کشف شده ایجاد می‌کند
- فیلدهای پر شده خودکار را در `discovered_fields` علامت‌گذاری می‌کند
- از IP تکراری برای یک کاربر جلوگیری می‌کند

**مجوز:** دسترسی نوشتن (write)

---

### **POST `/api/discovery/apply-bulk`** - اعمال کشف به چندین دارایی
**هدف:** به‌روزرسانی دسته‌جمعی چندین دارایی از نتایج اسکن

**درخواست:**
```json
[
  {
    "asset_id": 1,
    "ip_address": "192.168.1.10",
    "fields": ["hostname", "os_name"]
  },
  {
    "asset_id": 2,
    "ip_address": "192.168.1.20",
    "fields": ["mac_address"]
  }
]
```

**پارامتر Query:** `scan_id` (الزامی)

**برمی‌گرداند:** آرایه‌ای از نتایج (موفقیت/خطا) برای هر دارایی

**مجوز:** دسترسی نوشتن (write)

---

## **۵. اندپوینت‌های مدیریت پورت**

### **POST `/api/discovery/ports/add`** - اضافه کردن پورت‌ها به دارایی (غیرمخرب)
**هدف:** اضافه کردن پورت‌های تازه کشف شده بدون حذف پورت‌های موجود

**درخواست:**
```json
{
  "asset_id": 123,
  "scan_id": "ABC123",
  "ports": [
    {
      "port_number": 80,
      "protocol": "TCP",
      "service_name": "http",
      "state": "open"
    }
  ]
}
```

**رفتار:**
- فقط پورت‌هایی را اضافه می‌کند که قبلاً وجود ندارند
- رکوردهای پورت موجود را حفظ می‌کند
- برای به‌روزرسانی‌های تدریجی ایمن است

**مجوز:** دسترسی ویرایش (edit)

---

### **POST `/api/discovery/ports/overwrite`** - بازنویسی پورت‌های دارایی (مخرب)
**هدف:** جایگزینی تمام پورت‌ها با نتایج اسکن

**درخواست:** همانند `/add`

**رفتار:**
- **تمام پورت‌های موجود را حذف می‌کند**
- با پورت‌های جدید جایگزین می‌کند
- زمانی استفاده شود که نتایج اسکن منبع واحد حقیقت هستند

**مجوز:** دسترسی ویرایش (edit)

---

### **GET `/api/discovery/assets/{asset_id}/ports`** - دریافت پورت‌های دارایی
**هدف:** بازیابی تمام پورت‌ها برای یک دارایی

**برمی‌گرداند:**
```json
{
  "asset_id": 123,
  "total": 5,
  "ports": [...]
}
```

**مجوز:** دسترسی مشاهده (view)

---

### **DELETE `/api/discovery/ports/{port_id}`** - حذف پورت
**هدف:** حذف رکورد پورت خاص

**مجوز:** دسترسی حذف (delete)

---

## **سطوح مجوز**

تمام اندپوینت‌ها مجوزها را از طریق `check_discovery_permission()` بررسی می‌کنند:

- **نقش Admin:** دسترسی کامل به همه چیز
- **سایر نقش‌ها:** نیاز به مجوزهای خاص ماژول دارند:
  - `read`: مشاهده اسکن‌ها و هاست‌های در انتظار
  - `write`: شروع اسکن، تایید هاست‌ها
  - `edit`: تغییر داده‌های دارایی
  - `delete`: حذف اسکن‌ها و پورت‌ها
  - `view`: مشاهده جزئیات پورت

**ایزولاسیون کاربر:**
- کاربران غیر Admin فقط دارایی‌های خود را می‌بینند
- مطابقت دارایی مالکیت را رعایت می‌کند
- تایید/ادغام قبل از تغییر، مالکیت را بررسی می‌کند

---

## **جریان کاری معمول**

1. **شروع اسکن:** `POST /scan` → دریافت `scan_id`
2. **نظرسنجی وضعیت:** `GET /scan/{scan_id}` تا زمانی که `status="completed"`
3. **دریافت در انتظار:** `GET /pending` → لیست هاست‌های کشف شده
4. **بررسی مطابقت:** `GET /hosts/{host_id}/check-matches` → یافتن دارایی‌های موجود
5. **تایید/ایجاد:**
   - اگر مطابقت وجود دارد → `POST /hosts/{host_id}/approve` با `merge_with_existing`
   - اگر مطابقت وجود ندارد → `POST /hosts/{host_id}/approve` با `create_new`
6. **حذف هاست:** هاست‌های تایید شده از لیست در انتظار حذف می‌شوند، `matched_asset_id` تنظیم می‌شود

---

## **توضیحات تکمیلی**

### **نحوه عملکرد لینک Asset ID:**

- **ابتدا:** هاست‌های کشف شده `matched_asset_id = null` دارند، بنابراین ستون "-" را نشان می‌دهد
- **پس از تایید:** هنگامی که دارایی جدید ایجاد می‌کنید یا با موجود ادغام می‌کنید، بک‌اند `matched_asset_id` را به ID واقعی دارایی تنظیم می‌کند
- **پس از تازه‌سازی:** لیست هاست‌های در انتظار به طور خودکار تازه می‌شود و هاست‌های تایید/ادغام شده حذف می‌شوند (وضعیت از "pending" به "approved"/"merged" تغییر می‌کند)

### **فرمت‌های Target قابل قبول:**

- **IP تکی:** `192.168.1.1`
- **محدوده CIDR:** `192.168.1.0/24` (تمام IP‌ها از .0 تا .255)
- **محدوده IP:** `192.168.1.1-254` (از .1 تا .254)
- **چند IP:** از CIDR یا Range استفاده کنید

### **انواع اسکن و کاربرد:**

1. **well_known_ports (پیش‌فرض):**
   - پورت‌های 1-1024
   - سریع و کارآمد
   - برای اکثر شبکه‌های اداری کافی است

2. **all_ports:**
   - تمام 65535 پورت
   - بسیار کند (ممکن است ساعت‌ها طول بکشد)
   - برای ممیزی‌های امنیتی عمیق

3. **custom_ports:**
   - پورت‌های دلخواه شما
   - برای برنامه‌های خاص (مثلاً: 8080,8443,9000)

### **پروتکل‌ها:**

- **TCP:** معمول‌ترین (HTTP, SSH, FTP, etc.)
- **UDP:** کمتر متداول (DNS, DHCP, SNMP)
- **BOTH:** اسکن هر دو (کندتر)

### **وضعیت‌های Discovered Host:**

- `pending`: در انتظار بررسی کاربر
- `approved`: به عنوان دارایی جدید ایجاد شد
- `merged`: با دارایی موجود ادغام شد
- `skipped`: بررسی شد اما اقدامی نشد
- `rejected`: کاربر رد کرد

### **فیلدهای Auto-filled در دارایی:**

هنگام ایجاد دارایی از کشف، این فیلدها به طور خودکار پر می‌شوند:
- `ip_address`: از هاست کشف شده
- `hostname`: از نتایج اسکن
- `mac_address`: از نتایج اسکن
- `os_name`: از شناسایی سیستم‌عامل
- `os_version`: از شناسایی سیستم‌عامل

این فیلدها در JSON `discovered_fields` علامت‌گذاری می‌شوند تا فرانت‌اند بتواند آنها را به صورت بصری متمایز کند (مثلاً با رنگ نارنجی).

### **محدودیت‌ها و نکات امنیتی:**

1. **مالکیت دارایی:**
   - کاربران غیر Admin فقط می‌توانند دارایی‌های خود را مشاهده و تغییر دهند
   - تلاش برای ادغام با دارایی کاربر دیگر → خطای 403

2. **جلوگیری از IP تکراری:**
   - هر کاربر نمی‌تواند دو دارایی با یک IP داشته باشد
   - قبل از ایجاد دارایی جدید، سیستم IP را بررسی می‌کند

3. **Rate Limiting:**
   - اسکن‌های زیاد ممکن است منابع شبکه را مصرف کنند
   - توصیه می‌شود برنامه‌ریزی دقیق برای اسکن‌های بزرگ

4. **مجوزهای ماژول:**
   - هر کاربر باید مجوز `asset_auto_discovery` داشته باشد
   - مجوزها توسط مدیر سیستم تعیین می‌شوند

---

## **نمونه‌های کد استفاده (JavaScript/Frontend)**

### **مثال ۱: شروع اسکن و نظرسنجی نتایج**

```javascript
// شروع اسکن
const startScan = async () => {
  const response = await fetch('http://localhost:8000/api/discovery/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      target: '192.168.1.0/24',
      scan_type: 'well_known_ports',
      protocol: 'TCP'
    })
  });

  const scan = await response.json();
  console.log('Scan started:', scan.scan_id);

  // شروع نظرسنجی
  pollScanStatus(scan.scan_id);
};

// نظرسنجی وضعیت
const pollScanStatus = (scanId) => {
  const interval = setInterval(async () => {
    const response = await fetch(`http://localhost:8000/api/discovery/scan/${scanId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    const scan = await response.json();

    if (scan.status === 'completed') {
      clearInterval(interval);
      console.log('Scan completed! Hosts found:', scan.hosts_up);
      // دریافت هاست‌های در انتظار
      fetchPendingHosts();
    } else if (scan.status === 'failed') {
      clearInterval(interval);
      console.error('Scan failed:', scan.error);
    }
  }, 3000); // هر ۳ ثانیه
};
```

### **مثال ۲: بررسی مطابقت و تایید هاست**

```javascript
// بررسی مطابقت
const checkMatches = async (hostId) => {
  const response = await fetch(
    `http://localhost:8000/api/discovery/hosts/${hostId}/check-matches`,
    {
      headers: { 'Authorization': `Bearer ${token}` }
    }
  );

  const result = await response.json();

  if (result.matches.length > 0) {
    console.log('مطابقت پیدا شد:', result.matches[0]);
    // نمایش گزینه ادغام به کاربر
    showMergeOption(hostId, result.matches[0].asset_id);
  } else {
    console.log('مطابقت پیدا نشد - ایجاد دارایی جدید');
    showCreateNewOption(hostId);
  }
};

// ادغام با دارایی موجود
const mergeWithExisting = async (hostId, assetId) => {
  const response = await fetch(
    `http://localhost:8000/api/discovery/hosts/${hostId}/approve`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        action: 'merge_with_existing',
        asset_id: assetId
      })
    }
  );

  const result = await response.json();
  console.log('ادغام موفق:', result.message);
  console.log('فیلدهای به‌روزرسانی شده:', result.updated_fields);
};

// ایجاد دارایی جدید
const createNewAsset = async (hostId, assetName, assetTypeId) => {
  const response = await fetch(
    `http://localhost:8000/api/discovery/hosts/${hostId}/approve`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        action: 'create_new',
        asset_data: {
          asset_name: assetName,
          asset_type_id: assetTypeId
        }
      })
    }
  );

  const result = await response.json();
  console.log('دارایی ایجاد شد! Asset ID:', result.asset_id);
};
```

### **مثال ۳: تایید دسته‌جمعی**

```javascript
const bulkApprove = async (hostIds, defaultTypeId) => {
  const response = await fetch('http://localhost:8000/api/discovery/bulk-approve', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      host_ids: hostIds,
      default_asset_type_id: defaultTypeId
    })
  });

  const result = await response.json();
  console.log(`${result.approved} هاست تایید شد`);

  if (result.errors && result.errors.length > 0) {
    console.warn('خطاها:', result.errors);
  }
};
```

---

## **خطاهای رایج و راه‌حل‌ها**

### **خطا 400: "asset_data required for create_new action"**
**علت:** هنگام ایجاد دارایی جدید، `asset_data` ارسال نشده است
**راه‌حل:** مطمئن شوید که `asset_name` و `asset_type_id` را ارسال می‌کنید

### **خطا 403: "Not authorized to modify this asset"**
**علت:** سعی در تغییر دارایی کاربر دیگر
**راه‌حل:** فقط دارایی‌های خود را تغییر دهید یا با Admin وارد شوید

### **خطا 404: "Discovered host not found"**
**علت:** هاست قبلاً پردازش شده یا حذف شده است
**راه‌حل:** لیست pending را تازه کنید

### **خطا 404: "Asset not found"**
**علت:** ID دارایی اشتباه است
**راه‌حل:** از endpoint `/api/assets` برای دریافت لیست دارایی‌ها استفاده کنید

### **خطا 500: "Failed to start scan"**
**علت:** خطا در اجرای nmap یا فرمت target اشتباه
**راه‌حل:** فرمت target را بررسی کنید، مطمئن شوید nmap نصب است

---

## **بهترین شیوه‌ها (Best Practices)**

### **۱. مدیریت اسکن:**
- از `well_known_ports` برای اسکن‌های روتین استفاده کنید
- اسکن‌های بزرگ را در ساعات کم‌ترافیک اجرا کنید
- نتایج اسکن‌های قدیمی را حذف کنید تا دیتابیس شلوغ نشود

### **۲. پردازش هاست‌ها:**
- همیشه قبل از ایجاد دارایی جدید، مطابقت را بررسی کنید
- از bulk-approve برای اسکن‌های بزرگ استفاده کنید
- هاست‌های غیرمرتبط را reject کنید تا لیست تمیز بماند

### **۳. مدیریت پورت:**
- از `/ports/add` برای اسکن‌های تدریجی استفاده کنید
- از `/ports/overwrite` فقط زمانی استفاده کنید که اطمینان دارید
- قبل از overwrite، پورت‌های فعلی را بررسی کنید

### **۴. امنیت:**
- همیشه token را در header ارسال کنید
- مجوزهای کاربران را به درستی تنظیم کنید
- از HTTPS در محیط production استفاده کنید

---

## **نکات عملکردی (Performance Tips)**

### **بهینه‌سازی اسکن:**
1. از محدوده‌های کوچک‌تر شروع کنید
2. از custom_ports برای اهداف خاص استفاده کنید
3. فقط TCP را اسکن کنید مگر اینکه UDP لازم باشد

### **بهینه‌سازی نظرسنجی:**
1. فاصله polling را 3-5 ثانیه نگه دارید
2. بعد از complete شدن، polling را متوقف کنید
3. از WebSocket برای real-time updates استفاده کنید (اگر موجود باشد)

### **بهینه‌سازی داده:**
1. از pagination برای لیست‌های بزرگ استفاده کنید
2. فقط فیلدهای مورد نیاز را درخواست کنید
3. نتایج را در frontend کش کنید

---

این مستندات کامل تمام API endpoints موجود در ماژول Asset Auto Discovery را پوشش می‌دهد.

**تاریخ تهیه:** ۲۰۲۵-۱۲-۱۱
**نسخه API:** v1
**وضعیت:** فعال و در حال استفاده
