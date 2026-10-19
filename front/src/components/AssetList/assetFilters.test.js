import { describe, expect, it } from "vitest";
import { filterLabel, matchesFilters, readFilters } from "./assetFilters";

const params = (s) => new URLSearchParams(s);

describe("asset list filters from the address", () => {
    it("reads the known filters and drops unknown values", () => {
        expect(readFilters(params("missing=owner&type=3&added=7&q=x"))).toEqual([
            { key: "missing", value: "owner" }, { key: "type", value: "3" }, { key: "added", value: "7" },
        ]);
        expect(readFilters(params("missing=colour&added=-2&vendor="))).toEqual([]);
    });

    it("matches every filter", () => {
        const now = new Date("2099-06-01T12:00:00Z");
        const asset = { asset_type_id: 3, manufacturer: "Fortinet ", os_name: "FortiOS", status: "active",
                        owner_id: null, ip_address: "10.0.0.1", location_id: 2, created_at: "2099-05-28T10:00:00" };
        const m = (s) => matchesFilters(asset, readFilters(params(s)), now);
        expect(m("missing=owner")).toBe(true);
        expect(m("missing=ip")).toBe(false);
        expect(m("type=3&vendor=fortinet&os=FORTIOS&status=active")).toBe(true);
        expect(m("type=4")).toBe(false);
        expect(m("added=7")).toBe(true);        // four days old (a stored time without zone is UTC)
        expect(m("added=3")).toBe(false);
        expect(m("")).toBe(true);
    });

    it("names each filter", () => {
        expect(filterLabel({ key: "type", value: "3" }, () => "Firewall")).toContain("Firewall");
        expect(filterLabel({ key: "missing", value: "os" })).toBeTruthy();
    });
});
