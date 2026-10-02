import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDate, parseUtc } from "../../utils/dates.js";

// Shared labels for the remediation pages.

export const SEVERITY = {
    critical: { label: t("Critical"), pill: "rem-sev-critical" },
    high: { label: t("High"), pill: "rem-sev-high" },
    medium: { label: t("Medium"), pill: "rem-sev-medium" },
    low: { label: t("Low"), pill: "rem-sev-low" },
};

export const SOURCE = {
    cve: t("CVE"),
    audit: t("Audit"),
    arch: t("Architecture"),
};

export const STATUS = {
    open: { label: t("Open"), pill: "rem-st-open" },
    in_progress: { label: t("In progress"), pill: "rem-st-progress" },
    pending_verification: { label: t("Awaiting verification"), pill: "rem-st-verify" },
    resolved: { label: t("Fixed and verified"), pill: "rem-st-fixed" },
    accepted: { label: t("Risk accepted"), pill: "rem-st-accepted" },
};

export const ACCEPTANCE_STATUS = {
    pending: { label: t("Awaiting approval"), pill: "rem-st-verify" },
    approved: { label: t("Active"), pill: "rem-st-accepted" },
    rejected: { label: t("Rejected"), pill: "rem-st-rejected" },
    expired: { label: t("Expired"), pill: "rem-st-open" },
    revoked: { label: t("Withdrawn"), pill: "rem-st-open" },
};

export const CLOSED_REASON = {
    fixed: t("No longer reported by its source"),
    asset_deleted: t("The asset was deleted"),
    no_data: t("Its audit history was cleared"),
};

const DAY = 86400000;

/** Whole days from now to a deadline; negative when it has passed. */
export function daysLeft(value) {
    const d = parseUtc(value);
    if (!d) return null;
    return Math.round((d.getTime() - Date.now()) / DAY);
}

/** "3 days late" / "12 days left" / "due today". */
export function dueText(item) {
    const days = daysLeft(item.due_at);
    if (days === null) return "";
    if (days === 0) return t("due today");
    return days < 0 ? t("{{count}} days late", { count: -days }) : t("{{count}} days left", { count: days });
}

export function dueClass(item) {
    if (!item.due_at || !["open", "in_progress", "pending_verification"].includes(item.status)) return "";
    const days = daysLeft(item.due_at);
    if (days < 0) return "rem-due-over";
    if (days <= 7) return "rem-due-soon";
    return "";
}

export const shortDate = (value) => (value ? formatDate(value) : "—");

/** One line of a finding's history. */
export function eventText(e) {
    const d = e.data || {};
    switch (e.kind) {
        case "created": return t("Finding recorded; deadline {{date}}", { date: shortDate(d.due_at) });
        case "assigned":
            if (!d.owner_id) return t("Owner removed");
            return d.automatic ? t("Assigned to {{owner}} (owner of the asset)", { owner: d.owner || "?" })
                : t("Assigned to {{owner}}", { owner: d.owner || "?" });
        case "due_changed":
            return d.custom ? t("Deadline set to {{date}}", { date: shortDate(d.due_at) })
                : t("Deadline reset to the standard {{date}}", { date: shortDate(d.due_at) });
        case "status": return t("Status changed to {{status}}", { status: STATUS[d.new]?.label || d.new });
        case "note": return d.text || "";
        case "hardened": return t("Hardening applied successfully; waiting for the next audit to confirm");
        case "resolved": return CLOSED_REASON[d.reason] ? `${t("Closed")}: ${CLOSED_REASON[d.reason]}` : t("Closed");
        case "reopened": return t("Reported again by its source; reopened");
        case "acceptance_requested": return t("Risk acceptance requested until {{date}}", { date: shortDate(d.expires_at) });
        case "acceptance_approved": return t("Risk acceptance approved");
        case "acceptance_rejected": return t("Risk acceptance rejected");
        case "accepted": return t("Risk accepted until {{date}}", { date: shortDate(d.expires_at) });
        case "accepted_in_source": return t("Accepted on the Architecture Validation page");
        case "acceptance_ended": return t("Risk acceptance ended; the finding is open again");
        default: return e.kind;
    }
}

/** Where the finding lives in its own module. */
export function sourceLink(item) {
    const d = item.detail || {};
    if (item.source === "cve") return { to: "/cve", label: t("Open in CVE findings") };
    if (item.source === "audit" && d.session_id) return { to: `/audit/sessions/${d.session_id}`, label: t("Open the audit result") };
    if (item.source === "arch") return { to: "/architecture-validation", label: t("Open in Architecture Validation") };
    return null;
}

/** Title shown for an item: CVE descriptions and rule titles come from the API. */
export const itemTitle = (item) => (item.source === "arch" ? tb(item.title) : item.title);

export const count = (v) => n(v ?? 0);

export const errorText = (e, fallback) => {
    const detail = e?.response?.data?.detail;
    if (typeof detail === "string") return tb(detail);
    if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
    return fallback;
};
