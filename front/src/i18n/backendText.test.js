/**
 * Tests: audit trail details from the API read in Persian (tb, tbDetail).
 * The language is fixed when i18n loads, so it is set before the import.
 */
import { beforeAll, describe, expect, it } from "vitest";

let tb, tbDetail;

beforeAll(async () => {
    localStorage.setItem("lang", "fa");
    ({ tb, tbDetail } = await import("./backendText.js"));
});

describe("audit trail details in Persian", () => {
    it("translates a sentence with values, digits in Persian", () => {
        expect(tb("Exported 12 security events; filters: none")).toBe("خروجی ۱۲ رویداد امنیتی گرفته شد؛ فیلترها: هیچ");
        expect(tb("Login successful (role=admin)")).toMatch(/^ورود موفق \(نقش: /);
    });
    it("prefers the most specific sentence", () => {
        expect(tb("Deleted rule 'Disk full'")).toBe("قاعدهٔ «Disk full» حذف شد");
    });
    it("reads who changed a device and from where, not the generic 'from' sentence", () => {
        expect(tb("1 line(s) added and 0 removed; changed by netadmin, ops from 10.20.0.9, 10.20.0.10 (reported over syslog)"))
            .toBe("۱ خط افزوده و ۰ خط حذف شد؛ تغییر توسط netadmin, ops از \u206610.20.0.9, 10.20.0.10\u2069 (گزارش‌شده از راه syslog)");
        expect(tb("Changed by unknown user from 172.16.5.4; no scheduled backup covers this device"))
            .toBe("تغییر توسط کاربر نامشخص از 172.16.5.4؛ هیچ پشتیبان‌گیری زمان‌بندی‌شده‌ای این دستگاه را پوشش نمی‌دهد");
    });
    it("translates each part of a joined detail", () => {
        expect(tbDetail("NVD API key set; automatic update off"))
            .toBe("کلید API سامانهٔ NVD تنظیم شد؛ به‌روزرسانی خودکار خاموش");
    });
    it("leaves values and unknown text as they are", () => {
        expect(tbDetail("RA-2026-0007")).toBe("RA-2026-0007");
        expect(tbDetail("rows=3; filters=search=x")).toBe("rows=3; filters=search=x");
    });
});
