# Netease Frontend

## Brand: NGCORION

یک پیش‌نمایش کامل از فرانت‌اند سیستم مدیریت دارایی‌های شبکه

---

## ساختار فایل‌ها

```
frontend/
├── index.html          # صفحه لاگین
├── dashboard.html      # صفحه اصلی با سایدبار
├── css/
│   └── style.css       # همه استایل‌ها
├── js/
│   ├── app.js          # توابع اصلی (auth, navigation, permissions)
│   └── users.js        # مدیریت کاربران (CRUD)
└── README.md           # این فایل
```

---

## نحوه اجرا

### ۱. کپی فایل‌ها به پروژه

```bash
cp -r frontend/ /home/zi/Desktop/main_app/netease/
```

### ۲. اجرای سرور فرانت‌اند

```bash
cd /home/zi/Desktop/main_app/netease/frontend
python3 -m http.server 3000
```

### ۳. اجرای بک‌اند (در ترمینال دیگر)

```bash
cd /home/zi/Desktop/main_app/netease
source venv/bin/activate
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### ۴. باز کردن در مرورگر

```
http://localhost:3000
```

---

## قابلیت‌های فعلی

| صفحه | وضعیت | توضیحات |
|------|-------|---------|
| Login | ✅ کامل | احراز هویت با JWT |
| Dashboard | ✅ کامل | صفحه خانه با آمار |
| User Management | ✅ کامل | CRUD کاربران + permissions |
| Asset Requirement | ⏳ در انتظار | فرم درخواست دارایی |
| Asset List | ⏳ در انتظار | لیست دارایی‌ها |
| Auto Discovery | ⏳ در انتظار | کشف خودکار شبکه |
| Auditing | ⏳ در انتظار | ممیزی |
| Hardening | ⏳ در انتظار | امن‌سازی |
| Logs | ⏳ در انتظار | لاگ‌های سیستم |

---

## سیستم Permission

منوها بر اساس permissions کاربر نمایش داده می‌شوند:

- **Admin**: همه دسترسی‌ها
- **سایر کاربران**: فقط ماژول‌هایی که `read: true` دارند

### نمونه permissions:

```json
{
    "dashboard": {"read": true, "write": false, "delete": false},
    "asset_list": {"read": true, "write": true, "delete": false},
    "user_management": {"read": false, "write": false, "delete": false}
}
```

---

## تنظیمات

### تغییر آدرس API

در فایل `js/app.js` و `index.html`:

```javascript
const API_URL = 'http://localhost:8000';
```

---

## رنگ‌های برند

| رنگ | کد | استفاده |
|-----|-----|---------|
| Primary | `#00d4ff` | دکمه‌ها، لینک‌ها |
| Primary Dark | `#0099cc` | hover states |
| Sidebar | `#1a202c` | پس‌زمینه سایدبار |
| Text Dark | `#1a202c` | متن اصلی |
| Text Gray | `#718096` | متن ثانویه |

---

## برای فرانت‌اند کار

این پروژه با **Vanilla JavaScript** نوشته شده تا:
- ساختار و منطق واضح باشد
- قابل تبدیل به React/Vue باشد
- نیاز به build نداشته باشد

### نکات مهم:
1. همه توابع global هستند (برای سادگی)
2. `hasPermission(module, action)` برای چک کردن دسترسی
3. `apiRequest(endpoint, options)` برای API calls با token
4. `showPage(pageName)` برای navigation
5. هر صفحه می‌تونه `init_pagename()` داشته باشه که موقع نمایش صدا زده میشه

---

## توسعه آینده

برای اضافه کردن صفحه جدید:

1. HTML رو توی `dashboard.html` داخل `content-area` اضافه کن
2. JS رو توی فایل جدا (مثلاً `js/assets.js`) بنویس
3. فایل JS رو به `dashboard.html` اضافه کن
4. تابع `init_pagename()` بساز برای initialize شدن موقع نمایش صفحه
