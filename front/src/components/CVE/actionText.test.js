/**
 * Tests: the recommended action of a CVE finding reads as one sentence for each kind of fix.
 */
import { describe, expect, it } from "vitest";
import { actionText } from "./actionText.js";

const plain = (s) => s.replace(/[⁦-⁩]/g, "");

describe("actionText", () => {
    it("says what to do for each kind", () => {
        expect(plain(actionText({ kind: "package", product: "openssh", target: "1:9.6p1-3ubuntu13.3" })))
            .toBe("Upgrade openssh to 1:9.6p1-3ubuntu13.3 or later");
        expect(plain(actionText({ kind: "version", product: "Fortinet FortiOS", target: "7.2.9" })))
            .toBe("Upgrade Fortinet FortiOS to 7.2.9 or later");
        expect(plain(actionText({ kind: "after", product: "Openssl", target: "1.0.1f" })))
            .toBe("Upgrade Openssl to a version later than 1.0.1f");
        expect(plain(actionText({ kind: "windows", product: "Windows Server 2022", target: "10.0.20348.2655" })))
            .toBe("Install the latest cumulative update for Windows Server 2022 (build 10.0.20348.2655 or later)");
        expect(plain(actionText({ kind: "windows", product: "Windows Server 2022" })))
            .toBe("Install the latest cumulative update for Windows Server 2022");
        expect(plain(actionText({ kind: "reboot", target: "6.8.0-45.45" })))
            .toBe("Restart the machine: the fixed kernel 6.8.0-45.45 is installed but not running");
        expect(actionText({ kind: "advisory" })).toBe("No fixed version is known here: follow the vendor's advisory");
        expect(actionText(null)).toBe("");
    });

    it("keeps Latin names and versions in their own order inside a Persian sentence", () => {
        expect(actionText({ kind: "version", product: "FortiOS", target: "7.2.9" })).toContain("⁨FortiOS⁩");
    });
});
