/**
 * Tests: a page that throws while rendering shows a message with a way back instead of a white window,
 * and an API error list becomes text a page can show.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import { PageErrorBoundary } from "./PageErrorBoundary.jsx";
import { apiErrorText } from "../utils/apiError.js";

const Broken = () => {
    // what the scheduling page did: render FastAPI's list of {type, loc, msg, input} as a child
    const detail = { type: "int_parsing", loc: ["body", "group_id"], msg: "bad", input: "" };
    return <div>{detail}</div>;
};

describe("a page that crashes", () => {
    it("shows a message and keeps a way back", () => {
        const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
        render(<PageErrorBoundary><Broken /></PageErrorBoundary>);
        expect(screen.getByRole("alert").textContent).toContain("This page ran into a problem");
        expect(screen.getByRole("button", { name: "Reload page" })).toBeTruthy();
        expect(screen.getByRole("button", { name: "Go back" })).toBeTruthy();
        quiet.mockRestore();
    });

    it("renders the page when nothing goes wrong", () => {
        render(<PageErrorBoundary><p>fine</p></PageErrorBoundary>);
        expect(screen.getByText("fine")).toBeTruthy();
    });
});

describe("apiErrorText", () => {
    const err = (detail) => ({ response: { data: { detail } } });
    it("turns a refused body's list into one line naming each field", () => {
        expect(apiErrorText(err([
            { type: "int_parsing", loc: ["body", "group_id"], msg: "Input should be a valid integer", input: "" },
            { type: "value_error", loc: ["body"], msg: "Value error, Choose a target" },
        ]), "x")).toBe("group_id: Input should be a valid integer · Choose a target");
    });
    it("keeps a plain message and falls back when there is none", () => {
        expect(apiErrorText(err("Job not found"), "x")).toBe("Job not found");
        expect(apiErrorText(new Error("network"), "Could not save")).toBe("Could not save");
    });
});
