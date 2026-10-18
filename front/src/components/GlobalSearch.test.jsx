/**
 * Tests: the header search asks the server with ASCII digits, lists its results by kind with the menu's own
 * pages, and opens the chosen result with the keyboard.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { Provider } from "react-redux";
import { configureStore, createSlice } from "@reduxjs/toolkit";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";

const get = vi.fn();
vi.mock("../config/api.js", () => ({ default: { get: (...args) => get(...args) } }));

const { GlobalSearch } = await import("./GlobalSearch.jsx");

const auth = createSlice({ name: "auth", initialState: { role: "admin", permissions: {} }, reducers: {} });

function Where() {
    const loc = useLocation();
    return <p data-testid="where">{loc.pathname + loc.search}</p>;
}

const setup = () => {
    const store = configureStore({ reducer: { auth: auth.reducer } });
    render(
        <Provider store={store}>
            <MemoryRouter initialEntries={["/overview"]}>
                <GlobalSearch />
                <Routes><Route path="*" element={<Where />} /></Routes>
            </MemoryRouter>
        </Provider>,
    );
};

describe("global search", () => {
    beforeEach(() => {
        vi.useFakeTimers();
        get.mockReset();
    });

    it("searches with ASCII digits and opens a result with Enter", async () => {
        get.mockResolvedValue({ data: { query: "10.20", groups: [
            { kind: "assets", items: [{ id: 7, title: "fw-edge", detail: "10.20.0.1", link: "/assets/inventory/7" }] },
        ] } });
        setup();
        const box = screen.getByRole("combobox");
        fireEvent.focus(box);
        fireEvent.change(box, { target: { value: "۱۰.۲۰" } });
        await act(async () => { vi.advanceTimersByTime(300); });
        expect(get).toHaveBeenCalledWith("/api/search", { params: { q: "10.20", limit: 5 } });
        expect(screen.getByText("fw-edge")).toBeInTheDocument();
        fireEvent.keyDown(box, { key: "Enter" });
        expect(screen.getByTestId("where").textContent).toBe("/assets/inventory/7");
    });

    it("lists the menu's pages and moves with the arrows", async () => {
        get.mockResolvedValue({ data: { query: "backup", groups: [] } });
        setup();
        const box = screen.getByRole("combobox");
        fireEvent.focus(box);
        fireEvent.change(box, { target: { value: "backup" } });
        await act(async () => { vi.advanceTimersByTime(300); });
        const options = screen.getAllByRole("option");
        expect(options.length).toBeGreaterThan(1);
        fireEvent.keyDown(box, { key: "ArrowDown" });
        expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
        fireEvent.keyDown(box, { key: "Enter" });
        expect(screen.getByTestId("where").textContent).toMatch(/backup/);
    });

    it("says when nothing is found", async () => {
        get.mockResolvedValue({ data: { query: "zzqq", groups: [] } });
        setup();
        const box = screen.getByRole("combobox");
        fireEvent.focus(box);
        fireEvent.change(box, { target: { value: "zzqq" } });
        await act(async () => { vi.advanceTimersByTime(300); });
        expect(screen.getByText(/zzqq/)).toBeInTheDocument();
    });
});
