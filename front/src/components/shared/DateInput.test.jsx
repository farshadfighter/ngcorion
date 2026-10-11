/**
 * Tests: in Persian the date field shows and takes Jalali dates, and still hands the form ISO dates.
 * The language is fixed when i18n loads, so it is set before the component is imported.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

let DateInput, DateTimeInput;

beforeAll(async () => {
    localStorage.setItem("lang", "fa");
    ({ DateInput, DateTimeInput } = await import("./DateInput.jsx"));
});

describe("DateInput in Persian", () => {
    it("shows the ISO value as a Jalali date with Persian digits", () => {
        render(<DateInput value="2026-10-11" onChange={() => {}} aria-label="from" />);
        expect(screen.getByLabelText("from").value).toBe("۱۴۰۵/۰۷/۱۹");
    });

    it("turns a typed Jalali date into an ISO change event with the field's name", () => {
        const onChange = vi.fn();
        render(<DateInput name="last_audit_date" value="" onChange={onChange} aria-label="audit" />);
        const field = screen.getByLabelText("audit");
        fireEvent.change(field, { target: { value: "۱۴۰۵/۱/۱" } });
        fireEvent.blur(field);
        expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
            target: { name: "last_audit_date", value: "2026-03-21" },
        }));
    });

    it("refuses a date outside min/max or one that does not exist, and keeps the value", () => {
        const onChange = vi.fn();
        render(<DateInput value="" min="2026-10-01" max="2026-10-31" onChange={onChange} aria-label="until" />);
        const field = screen.getByLabelText("until");
        fireEvent.change(field, { target: { value: "1405/08/15" } }); // 2026-11-06, after max
        fireEvent.blur(field);
        fireEvent.change(field, { target: { value: "1405/07/31" } }); // Mehr has 30 days
        fireEvent.keyDown(field, { key: "Enter" });
        expect(onChange).not.toHaveBeenCalled();
        expect(field.getAttribute("aria-invalid")).toBe("true");
    });

    it("picks a day from the month calendar", () => {
        const onChange = vi.fn();
        render(<DateInput value="2026-10-11" onChange={onChange} aria-label="d" />);
        fireEvent.click(screen.getByRole("button", { name: "انتخاب تاریخ" }));
        expect(screen.getByText("مهر ۱۴۰۵")).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "۱۴۰۵/۰۷/۲۵" }));
        expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ target: { name: undefined, value: "2026-10-17" } }));
    });

    it("keeps the time of a date and time value", () => {
        const onChange = vi.fn();
        render(<DateTimeInput value="2026-10-11T14:30" onChange={onChange} aria-label="when" />);
        const field = screen.getByLabelText("when");
        fireEvent.change(field, { target: { value: "1405/07/20" } });
        fireEvent.blur(field);
        expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ target: { name: undefined, value: "2026-10-12T14:30" } }));
    });
});
