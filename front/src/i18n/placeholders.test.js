/**
 * Tests: every Persian translation carries the same {{placeholders}} as its English key. A renamed or
 * dropped placeholder shows the raw "{{count, number}}" (or nothing) on screen instead of the value.
 */
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

const dir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "locales/fa");
const names = (s) => [...new Set([...String(s).matchAll(/\{\{\s*(\w+)/g)].map((m) => m[1]))].sort();

describe("Persian translations", () => {
    it("keep the placeholders of their English text", () => {
        const wrong = [];
        for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json"))) {
            const strings = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
            for (const [en, fa] of Object.entries(strings)) {
                if (fa && names(en).join() !== names(fa).join()) wrong.push(`${file}: ${en} -> ${fa}`);
            }
        }
        expect(wrong).toEqual([]);
    });

    it("do not put a middle dot next to a number", () => {
        // "·" beside a Persian digit reads as a zero (۲۴ · → ۲۴۰); Persian separates with "،".
        const wrong = [];
        for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json"))) {
            const strings = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
            for (const [en, fa] of Object.entries(strings)) {
                if (fa && /·\s*[۰-۹0-9{]|[۰-۹0-9}]\s*·/.test(fa)) wrong.push(`${file}: ${en} -> ${fa}`);
            }
        }
        expect(wrong).toEqual([]);
    });
});
