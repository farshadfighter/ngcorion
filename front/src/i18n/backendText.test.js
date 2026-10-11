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
    it("translates each part of a joined detail", () => {
        expect(tbDetail("NVD API key set; automatic update off"))
            .toBe("کلید API سامانهٔ NVD تنظیم شد؛ به‌روزرسانی خودکار خاموش");
    });
    it("leaves values and unknown text as they are", () => {
        expect(tbDetail("RA-2026-0007")).toBe("RA-2026-0007");
        expect(tbDetail("rows=3; filters=search=x")).toBe("rows=3; filters=search=x");
    });
});
