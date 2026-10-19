/**
 * Tests: the expanded sidebar opens one group at a time; going to a page opens that page's group.
 */
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { SidebarNav } from "./SidebarNav.jsx";

const auth = { role: "admin", permissions: {} };
const nav = (pageKey) => (
    <MemoryRouter><SidebarNav auth={auth} pageKey={pageKey} collapsed={false} alertSummary={null} /></MemoryRouter>
);
const head = (label) => screen.getByRole("button", { name: label });
const openGroups = () => screen.getAllByRole("button", { expanded: true }).map((b) => b.textContent.trim());

describe("sidebar groups", () => {
    it("starts with only the current page's group open", () => {
        render(nav("asset-list"));
        expect(openGroups()).toEqual(["Assets"]);
        expect(screen.getByRole("link", { name: "Asset List" })).toBeTruthy();
        expect(screen.queryByRole("link", { name: "Run audits" })).toBeNull();
    });

    it("opening a group closes the open one; opening it again closes it", () => {
        render(nav("asset-list"));
        fireEvent.click(head("Security assessment"));
        expect(openGroups()).toEqual(["Security assessment"]);
        expect(screen.queryByRole("link", { name: "Asset List" })).toBeNull();
        fireEvent.click(head("Security assessment"));
        expect(screen.queryAllByRole("button", { expanded: true })).toEqual([]);
    });

    it("the current page's group can be closed too", () => {
        render(nav("asset-list"));
        fireEvent.click(head("Assets"));
        expect(screen.queryAllByRole("button", { expanded: true })).toEqual([]);
    });

    it("going to a page in another group opens that group and closes the rest", () => {
        const { rerender } = render(nav("asset-list"));
        fireEvent.click(head("Reports"));
        rerender(nav("cve"));
        expect(openGroups()).toEqual(["Security assessment"]);
    });

    it("another page of the same group (e.g. from the search) opens that group again", () => {
        const { rerender } = render(nav("asset-list"));
        fireEvent.click(head("Reports"));
        rerender(nav("asset-groups"));
        expect(openGroups()).toEqual(["Assets"]);
    });

    it("a page without a group (the dashboard) leaves every group closed", () => {
        render(nav("dashboard"));
        expect(screen.queryAllByRole("button", { expanded: true })).toEqual([]);
    });
});
