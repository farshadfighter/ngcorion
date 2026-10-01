import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../config/api.js";
import { parseUtc } from "../../utils/dates.js";
import { MODULES, SEVERITY } from "./alertFormat.js";

function ago(value) {
    const d = parseUtc(value);
    if (!d) return "";
    const min = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
    if (min < 1) return "just now";
    if (min < 60) return `${min} min ago`;
    const h = Math.round(min / 60);
    if (h < 24) return `${h} h ago`;
    const days = Math.round(h / 24);
    return days === 1 ? "yesterday" : `${days} days ago`;
}

/** Header bell: unread count, the latest alerts, and a way to the Alerts page. */
export function AlertBell({ summary, onChanged }) {
    const [open, setOpen] = useState(false);
    const ref = useRef(null);
    const navigate = useNavigate();
    const unread = summary?.unread || 0;
    const seenAt = parseUtc(summary?.seen_at);

    useEffect(() => {
        if (!open) return undefined;
        const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
        const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
        document.addEventListener("mousedown", onDown);
        document.addEventListener("keydown", onKey);
        return () => {
            document.removeEventListener("mousedown", onDown);
            document.removeEventListener("keydown", onKey);
        };
    }, [open]);

    const markRead = () => api.post("/api/alerts/seen").then(onChanged).catch(() => {});
    const go = (path) => { setOpen(false); navigate(path); };

    return (
        <div className="alr-bell-wrap" ref={ref}>
            <button type="button" className={`alr-bell ${open ? "is-open" : ""}`}
                    aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
                    aria-expanded={open} aria-haspopup="dialog"
                    onClick={() => setOpen((v) => !v)}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                     strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0" />
                </svg>
                {unread > 0 && <span className="alr-bell-count">{unread > 99 ? "99+" : unread}</span>}
            </button>
            {open && (
                <div className="alr-dd" role="dialog" aria-label="Notifications">
                    <div className="alr-dd-head">
                        <b>Notifications</b>
                        {unread > 0 && <button type="button" className="bkm-link" onClick={markRead}>Mark all read</button>}
                    </div>
                    {(summary?.latest || []).length === 0 ? (
                        <div className="alr-dd-empty">No alerts yet. When something needs attention, it shows up here.</div>
                    ) : (
                        <ul className="alr-dd-list">
                            {summary.latest.map((a) => {
                                const isNew = a.status !== "resolved" && (!seenAt || parseUtc(a.first_seen_at) > seenAt);
                                return (
                                    <li key={a.id}>
                                        <button type="button" className={`alr-dd-item ${isNew ? "is-new" : ""}`}
                                                onClick={() => go(a.link || "/alerts")}>
                                            <span className="alr-dot" aria-hidden="true"
                                                  style={{ background: a.status === "resolved" ? "#94a3b8" : SEVERITY[a.severity]?.dot }} />
                                            <span className="alr-dd-text">
                                                <b>{a.title}{a.source ? ` · ${a.source.split(" · ")[0]}` : ""}</b>
                                                <span>
                                                    {MODULES[a.module] || a.module} · {ago(a.first_seen_at)}
                                                    {a.status === "resolved" ? " · resolved" : a.status === "acknowledged" ? ` · acknowledged by ${a.acknowledged_by}` : ""}
                                                </span>
                                            </span>
                                        </button>
                                    </li>
                                );
                            })}
                        </ul>
                    )}
                    <div className="alr-dd-foot">
                        <button type="button" className="bkm-link" onClick={() => go("/alerts")}>View all alerts →</button>
                    </div>
                </div>
            )}
        </div>
    );
}
