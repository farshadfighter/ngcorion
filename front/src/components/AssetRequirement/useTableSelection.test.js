import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useTableSelection } from "./useTableSelection.js";

const rows = (n) => Array.from({ length: n }, (_, i) => ({ id: i + 1 }));

describe("useTableSelection", () => {
    it("pages the rows", () => {
        const { result } = renderHook(({ list }) => useTableSelection(list), { initialProps: { list: rows(60) } });
        expect(result.current.paged).toHaveLength(25);
    });

    it("goes back to page 1 when the list shrinks past the current page", () => {
        const { result, rerender } = renderHook(({ list }) => useTableSelection(list), { initialProps: { list: rows(60) } });
        act(() => result.current.setPage(3));
        expect(result.current.paged[0].id).toBe(51);
        rerender({ list: rows(10) });
        expect(result.current.page).toBe(1);
        expect(result.current.paged).toHaveLength(10);
    });

    it("drops selected rows that disappear", () => {
        const { result, rerender } = renderHook(({ list }) => useTableSelection(list), { initialProps: { list: rows(5) } });
        act(() => { result.current.toggleOne(2); result.current.toggleOne(4); });
        expect(result.current.selectedIds.size).toBe(2);
        rerender({ list: rows(3) });                   // id 4 is gone
        expect([...result.current.selectedIds]).toEqual([2]);
    });
});
