import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AlertBell } from "./AlertBell.jsx";
import { actionLabel } from "./alertFormat.js";

vi.mock("../../config/api.js", () => ({ default: { post: vi.fn(() => Promise.resolve({ data: {} })) } }));

const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();

const summary = {
    unread: 2,
    seen_at: minutesAgo(30),
    latest: [
        { id: 1, title: "Device unreachable", source: "RTR-Branch-03 · 10.23.0.1", module: "noc",
          severity: "critical", status: "active", first_seen_at: minutesAgo(11), link: "/noc/hosts/3" },
        { id: 2, title: "Interface down", source: "SW-Access-14 · 10.3.14.2", module: "noc",
          severity: "warning", status: "acknowledged", acknowledged_by: "s.ahmadi",
          first_seen_at: minutesAgo(120), link: "/noc/hosts/4" },
    ],
};

const setup = (s = summary, onChanged = vi.fn()) => {
    render(<MemoryRouter><AlertBell summary={s} onChanged={onChanged} /></MemoryRouter>);
    return onChanged;
};

describe("AlertBell", () => {
    it("shows the unread count in its label and badge", () => {
        setup();
        const bell = screen.getByRole("button", { name: "Notifications, 2 unread" });
        expect(bell).toHaveTextContent("2");
    });

    it("lists the latest alerts when opened and closes on Escape", () => {
        setup();
        fireEvent.click(screen.getByRole("button", { name: /Notifications/ }));
        expect(screen.getByRole("dialog", { name: "Notifications" })).toBeInTheDocument();
        expect(screen.getByText("Device unreachable · RTR-Branch-03")).toBeInTheDocument();
        expect(screen.getByText(/acknowledged by s\.ahmadi/)).toBeInTheDocument();
        fireEvent.keyDown(document, { key: "Escape" });
        expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("offers Mark all read only when something is unread", () => {
        setup({ ...summary, unread: 0 });
        fireEvent.click(screen.getByRole("button", { name: "Notifications" }));
        expect(screen.queryByRole("button", { name: "Mark all read" })).toBeNull();
    });

    it("says when there is nothing yet", () => {
        setup({ unread: 0, latest: [] });
        fireEvent.click(screen.getByRole("button", { name: "Notifications" }));
        expect(screen.getByText(/No alerts yet/)).toBeInTheDocument();
    });
});

describe("actionLabel", () => {
    it("names what the link opens", () => {
        expect(actionLabel({ link: "/noc/hosts/3" })).toBe("Open host");
        expect(actionLabel({ link: "/cve/database" })).toBe("Open database");
        expect(actionLabel({ link: "/cve" })).toBe("Open CVE findings");
        expect(actionLabel({ link: "/backup/restores?restore=1" })).toBe("Open restore");
        expect(actionLabel({ link: "/audit/schedule-auditing" })).toBe("Open job");
    });
});
