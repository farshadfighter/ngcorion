import { describe, expect, it } from "vitest";
import { deviceLabel, typeFor, typeHint } from "./newBackupForm.js";

const fw = { asset_id: 5, asset_name: "fw-dc", ip_address: "172.16.120.1", family: "fortinet" };
const box = { asset_id: 9, asset_name: "box-1", ip_address: null, family: null };

describe("new backup form", () => {
    it("labels a device with its address and detected family", () => {
        expect(deviceLabel(fw)).toBe("fw-dc (172.16.120.1) · FortiGate");
        expect(deviceLabel(box)).toBe("box-1 - no IP address");
    });

    it("follows the asset's detected family, or leaves it to choose", () => {
        expect(typeFor(fw)).toBe("fortinet");
        expect(typeFor(box)).toBe("");
        expect(typeFor(undefined)).toBe("");
    });

    it("says where the type came from", () => {
        expect(typeHint(fw, "fortinet")).toBe("Detected from the asset: FortiGate");
        expect(typeHint(fw, "linux")).toBe("Detected as FortiGate; the backup is taken as Linux.");
        expect(typeHint(box, "")).toMatch(/choose it/);
        expect(typeHint(null, "")).toBe("");
    });
});
