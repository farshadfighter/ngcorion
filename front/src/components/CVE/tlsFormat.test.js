import { beforeAll, describe, expect, it } from "vitest";

let commonName, problemText;

beforeAll(async () => {
    localStorage.setItem("lang", "en");
    ({ commonName, problemText } = await import("./tlsFormat.js"));
});

describe("TLS certificate helpers", () => {
    it("takes the common name of a distinguished name", () => {
        expect(commonName("CN=fw.corp.local,O=Corp")).toBe("fw.corp.local");
        expect(commonName("O=Corp,CN=Acme\\, Inc. CA")).toBe("Acme, Inc. CA");
        expect(commonName("O=Corp")).toBe("O=Corp");
        expect(commonName(null)).toBe("—");
    });
    it("says each problem in one line", () => {
        expect(problemText({ code: "weak_key", key: "RSA 1024" })).toBe("Weak key: RSA 1024");
        expect(problemText({ code: "untrusted", self_signed: true })).toBe("Self-signed");
        expect(problemText({ code: "old_protocol", protocols: ["TLS 1.0", "TLS 1.1"] })).toBe("Accepts TLS 1.0, TLS 1.1");
    });
});
