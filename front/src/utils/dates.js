// Dates as the API sends them: naive UTC timestamps ("2026-10-01T02:00:00").

export function parseUtc(value) {
    if (!value) return null;
    const s = String(value);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) || s.length <= 10 ? s : `${s}Z`);
    return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n) => String(n).padStart(2, "0");

export function formatWhen(value) {
    const d = parseUtc(value);
    if (!d) return "—";
    const now = new Date();
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const diff = Math.round((today - day) / 86400000);
    if (diff === 0) return `Today ${time}`;
    if (diff === 1) return `Yesterday ${time}`;
    return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })} ${time}`;
}

export function formatDate(value) {
    const d = parseUtc(value);
    return d ? d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—";
}

export function ageDays(value) {
    const d = parseUtc(value);
    return d ? (Date.now() - d.getTime()) / 86400000 : null;
}


/** "Today", "Yesterday", "12 days ago". */
export function relativeDays(value) {
    const days = ageDays(value);
    if (days == null) return "—";
    const n = Math.floor(days);
    return n <= 0 ? "Today" : n === 1 ? "Yesterday" : `${n} days ago`;
}

/** Time between two timestamps: "20 s", "2 min", "1 h 05 min". */
export function duration(start, end) {
    const a = parseUtc(start), b = parseUtc(end);
    if (!a || !b) return null;
    const s = Math.max(0, Math.round((b - a) / 1000));
    if (s < 60) return `${s} s`;
    const m = Math.round(s / 60);
    return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${pad(m % 60)} min`;
}
