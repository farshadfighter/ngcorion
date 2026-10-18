/**
 * Tests: translated sentences with Latin values render with each value isolated, one-word values kept
 * on one line, and a Persian sentence laid out right to left even when it opens with a Latin word.
 */
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { BidiText } from "./BidiText.jsx";

describe("BidiText", () => {
    it("returns text without isolated values unchanged", () => {
        const { container } = render(<p><BidiText text="old_value=none; score=40.0" /></p>);
        expect(container.querySelector("bdi")).toBeNull();
        expect(container.textContent).toBe("old_value=none; score=40.0");
    });
    it("isolates values and keeps one-word ones on one line", () => {
        const { container } = render(<p><BidiText text={"⁨core-sw-01⁩ پورت ⁨Hangzhou Hikvision⁩"} /></p>);
        const bdis = container.querySelectorAll("bdi");
        expect([...bdis].map((b) => b.textContent)).toEqual(["core-sw-01", "Hangzhou Hikvision"]);
        expect(bdis[0].className).toBe("bidi-word");
        expect(bdis[1].className).toBe("");
        expect(container.querySelector("span[dir=rtl]")).not.toBeNull();
        expect(container.textContent).not.toMatch(/[⁨⁩]/);
    });
});
