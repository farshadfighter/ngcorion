import { describe, expect, it } from "vitest";
import { hostChoices, isVirtualType, requiresHosting } from "./assetHosting";

const TYPES = [{ id: 1, type_name: "Physical Server", is_virtual: false }, { id: 2, type_name: "Guest", is_virtual: true }];
const ASSETS = [{ id: 10, asset_type_id: 1 }, { id: 11, asset_type_id: 2 }, { id: 12, asset_type_id: 1 }];

describe("asset hosting", () => {
    it("asks a virtual type, or a VM/app/database by name, for its host", () => {
        expect(requiresHosting(TYPES[1])).toBe(true);
        expect(requiresHosting(TYPES[0])).toBe(false);
        expect(requiresHosting({ type_name: "VM", is_virtual: false })).toBe(true);
        expect(requiresHosting("Database")).toBe(true);
        expect(requiresHosting(undefined)).toBe(false);
        expect(isVirtualType(TYPES[1])).toBe(true);
    });
    it("offers a virtual asset only physical hosts, and never the asset itself", () => {
        expect(hostChoices(ASSETS, TYPES, { virtual: true }).map((a) => a.id)).toEqual([10, 12]);
        expect(hostChoices(ASSETS, TYPES, { virtual: false, selfId: 12 }).map((a) => a.id)).toEqual([10, 11]);
    });
});
