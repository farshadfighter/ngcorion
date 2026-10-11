/**
 * Tests: the sidebar shows each user exactly the entries their permissions open, every entry points
 * at a page the router knows, and every page key lights up exactly one entry.
 */
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { MENU_GROUPS, TOP_ITEMS, groupOf, menuFromPath, visibleMenu } from "./sidebarMenu.js";

const labels = (menu) => [...menu.top.map((i) => i.key), ...menu.groups.flatMap((g) => [g.id, ...g.items.map((i) => i.key)])];
const read = (modules) => Object.fromEntries(modules.map((m) => [m, { read: true, write: false, delete: false }]));

describe("sidebar menu", () => {
    it("shows a system administrator everything, in the agreed order", () => {
        const menu = visibleMenu({ role: "admin", permissions: {} });
        expect(menu.groups.map((g) => g.id))
            .toEqual(["assets", "assessment", "remediation", "device-backups", "network", "reports", "admin"]);
        expect(menu.groups.every((g) => g.items.length <= 7)).toBe(true);
    });

    it("shows a user with the default permissions only what they can open", () => {
        const menu = visibleMenu({ role: "user", permissions: read(["dashboard", "asset_list"]) });
        expect(labels(menu)).toEqual(["dashboard", "alerts", "assets", "asset-management", "asset-list", "software"]);
    });

    it("never shows risk, the license or the NGCorion backup without the right to open them", () => {
        const keys = labels(visibleMenu({ role: "manager", permissions: read(["system_config", "logs"]) }));
        expect(keys).not.toContain("risk-intelligence");
        expect(keys).not.toContain("licence");
        expect(keys).not.toContain("system-backup");
        expect(keys).toEqual(expect.arrayContaining(["system-configuration", "notifications", "audit-trail"]));
    });

    it("points every entry at a route App.jsx defines", () => {
        const app = fs.readFileSync(path.resolve(path.dirname(new URL(import.meta.url).pathname), "../App.jsx"), "utf8");
        const routes = new Set([...app.matchAll(/path="([^"]+)"/g)].map((m) => m[1]));
        for (const item of [...TOP_ITEMS, ...MENU_GROUPS.flatMap((g) => g.items)]) {
            expect(routes.has(item.path), item.path).toBe(true);
            expect(menuFromPath(item.path), item.path).toBe(item.key);
        }
    });

    it("finds the group of a page, including the logs page that shares an entry", () => {
        expect(groupOf(menuFromPath("/settings/logs"))).toBe("admin");
        expect(groupOf(menuFromPath("/audit/sessions/12"))).toBe("assessment");
        expect(groupOf(menuFromPath("/overview"))).toBeUndefined();
    });
});
