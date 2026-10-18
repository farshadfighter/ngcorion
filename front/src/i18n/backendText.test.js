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
        expect(tb("Deleted rule 'Disk full'")).toBe("قاعدهٔ «\u2068Disk full\u2069» حذف شد");
    });
    it("reads who changed a device and from where, not the generic 'from' sentence", () => {
        expect(tb("1 line(s) added and 0 removed; changed by netadmin, ops from 10.20.0.9, 10.20.0.10 (reported over syslog)"))
            .toBe("۱ خط افزوده و ۰ خط حذف شد؛ تغییر توسط \u2068netadmin, ops\u2069 از \u206610.20.0.9, 10.20.0.10\u2069 (گزارش‌شده از راه syslog)");
        expect(tb("Changed by unknown user from 172.16.5.4; no scheduled backup covers this device"))
            .toBe("تغییر توسط کاربر نامشخص از 172.16.5.4؛ هیچ پشتیبان‌گیری زمان‌بندی‌شده‌ای این دستگاه را پوشش نمی‌دهد");
    });
    it("keeps Latin names whole inside a Persian sentence", () => {
        expect(tb("core-sw-01 port GigabitEthernet1/0/2 to dist-switch-02 port Gi1/0/48 is no longer reported by LLDP/CDP"))
            .toBe("\u2068core-sw-01\u2069 پورت \u2068GigabitEthernet1/0/2\u2069 به \u2068dist-switch-02\u2069 پورت "
                + "\u2068Gi1/0/48\u2069 دیگر در LLDP/CDP گزارش نمی‌شود");
        // digits alone become Persian and need no isolation; a translated value stays as it is
        expect(tb("{{count}} addresses that are not assets appeared".replace("{{count}}", "12"))).not.toMatch(/\u2068/);
    });
    it("reads a day from the API as a Persian date", () => {
        const text = tb("nginx 1.18 on web-01: support ended 2021-04-20");
        expect(text).toMatch(/پشتیبانی در .*۱۴۰۰ تمام شد$/);
        expect(text).not.toMatch(/2021/);
    });
    it("reads TLS certificate findings", () => {
        expect(tb("The certificate of 10.0.0.5:443 is self-signed")).toBe("گواهی 10.0.0.5:443 خودامضاست");
        expect(tb("The certificate of 10.0.0.5:443 expired on 2026-10-01")).toMatch(/^گواهی .* در .*۱۴۰۵ منقضی شده است$/);
        expect(tb("10.0.0.5:636 still accepts TLS 1.0, TLS 1.1")).toMatch(/هنوز .*TLS 1\.0, TLS 1\.1.* را می‌پذیرد$/);
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
