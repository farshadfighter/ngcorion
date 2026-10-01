import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Changes, RestoreResult } from "./RestoreDetailDrawer.jsx";

describe("RestoreResult", () => {
    it.each([
        ["succeeded", "Succeeded"],
        ["reverted", "Reverted automatically"],
        ["failed", "Failed"],
        ["applying", "In progress"],
    ])("%s reads %s", (status, label) => {
        render(<RestoreResult status={status} />);
        expect(screen.getByText(label)).toBeInTheDocument();
    });

    it("short form keeps the full text as a tooltip", () => {
        render(<RestoreResult status="reverted" short />);
        expect(screen.getByText("Reverted")).toHaveAttribute("title", "Reverted automatically");
    });
});

describe("Changes", () => {
    it("shows added and removed lines", () => {
        render(<Changes diff={{ added: 4, removed: 12 }} />);
        expect(screen.getByText("+4")).toBeInTheDocument();
        expect(screen.getByText("−12")).toBeInTheDocument();
    });
    it("shows a dash without a diff", () => {
        render(<Changes diff={null} />);
        expect(screen.getByText("—")).toBeInTheDocument();
    });
});
