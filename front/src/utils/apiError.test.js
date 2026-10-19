import { describe, expect, it } from "vitest";
import { apiErrorDetail, noAnswerText } from "./apiError.js";

const err = (detail) => ({ response: { data: { detail } } });

describe("apiErrorDetail (what a slice keeps as its error)", () => {
    it("keeps the server's text unchanged, so pages can still translate or compare it", () => {
        expect(apiErrorDetail(err("Asset type with this name already exists"), "x"))
            .toBe("Asset type with this name already exists");
    });
    it("makes a refused body's list one line naming each field", () => {
        expect(apiErrorDetail(err([
            { type: "missing", loc: ["body", "name"], msg: "Field required" },
            { type: "int_parsing", loc: ["body", "ports", 0], msg: "Input should be a valid integer" },
        ]), "x")).toBe("name: Field required · ports.0: Input should be a valid integer");
    });
    it("takes the message of an error object", () => {
        expect(apiErrorDetail(err({ error_type: "authentication_error", message: "SSH authentication failed" }), "x"))
            .toBe("SSH authentication failed");
    });
    it("falls back when the server said nothing usable", () => {
        expect(apiErrorDetail(err([]), "Failed to load")).toBe("Failed to load");
        expect(apiErrorDetail(err({ code: 7 }), "Failed to load")).toBe("Failed to load");
        expect(apiErrorDetail(new Error("Network Error"), "Failed to load")).toBe("Failed to load");
    });
});

describe("noAnswerText (no message from the server)", () => {
    it("says the request ran out of time, which is not a failure of the work itself", () => {
        expect(noAnswerText({ code: "ECONNABORTED", request: {} })).toMatch(/did not answer in time/);
    });
    it("says nothing answered when no response came back", () => {
        expect(noAnswerText({ request: {}, message: "Network Error" })).toMatch(/could not be reached/);
    });
    it("names a 5xx that came back without a message", () => {
        expect(noAnswerText({ response: { status: 500, data: "Internal Server Error" } })).toMatch(/error 500/);
        expect(noAnswerText({ response: { status: 504, data: "<html>" } })).toMatch(/error 504/);
    });
    it("leaves an answered request to the caller's own sentence", () => {
        expect(noAnswerText({ response: { status: 422, data: {} } })).toBeNull();
        expect(noAnswerText(undefined)).toBeNull();
    });
});
