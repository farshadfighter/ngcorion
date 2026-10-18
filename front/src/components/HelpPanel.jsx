import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { t, currentLanguage } from "../i18n";
import { blocks, hasHelp, inline, loadHelp } from "../help";
// The drawer and scrim are the shared .bkm-* ones.
import "../assets/BackupModule.css";
import "../assets/Help.css";

/** Text with the search words marked. */
const Marked = ({ text, q }) => {
    if (!q) return text;
    const parts = [];
    const lower = text.toLowerCase();
    let from = 0;
    for (let at = lower.indexOf(q); at !== -1; at = lower.indexOf(q, at + q.length)) {
        if (at > from) parts.push(text.slice(from, at));
        parts.push(<mark key={at}>{text.slice(at, at + q.length)}</mark>);
        from = at + q.length;
    }
    parts.push(text.slice(from));
    return parts;
};

const Inline = ({ text, onNavigate, q }) => inline(text).map((p, i) => {
    if (p.type === "b") return <strong key={i}><Marked text={p.text} q={q} /></strong>;
    if (p.type === "code") return <code key={i} dir="ltr">{p.text}</code>;
    if (p.type === "link") {
        // Only pages of NGCorion itself; anything else stays plain text.
        return p.to.startsWith("/") ? <Link key={i} to={p.to} onClick={onNavigate}>{p.text}</Link> : <span key={i}>{p.text}</span>;
    }
    return <span key={i}><Marked text={p.text} q={q} /></span>;
});

const Body = ({ text, onNavigate, q }) => blocks(text).map((b, i) => {
    if (b.type === "table") {
        return (
            <div className="hlp-table-wrap" key={i}>
                <table className="hlp-table">
                    <thead><tr>{b.head.map((c, j) => <th key={j}><Inline text={c} q={q} /></th>)}</tr></thead>
                    <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}><Inline text={c} onNavigate={onNavigate} q={q} /></td>)}</tr>)}</tbody>
                </table>
            </div>
        );
    }
    if (b.type === "ul" || b.type === "ol") {
        const List = b.type;
        return <List key={i} start={b.start}>{b.items.map((it, j) => <li key={j}><Inline text={it} onNavigate={onNavigate} q={q} /></li>)}</List>;
    }
    if (b.type === "pre") {
        return <pre className="hlp-pre" dir="ltr" key={i}><code>{b.text}</code></pre>;
    }
    if (b.type === "note") {
        return (
            <div className="hlp-note" key={i}>
                <i className="fa-solid fa-triangle-exclamation" aria-hidden="true" />
                <p><Inline text={b.text} onNavigate={onNavigate} q={q} /></p>
            </div>
        );
    }
    return <p key={i}><Inline text={b.text} onNavigate={onNavigate} q={q} /></p>;
});

/**
 * Help for the page that is open: its summary, then foldable sections, with a search over them.
 * `section` opens one section and scrolls to it (a link from the global search).
 */
export function HelpPanel({ pageKey, section = null, onClose }) {
    const [help, setHelp] = useState(undefined);
    const [query, setQuery] = useState("");
    const [open, setOpen] = useState(section ? { [section]: true } : {});
    const body = useRef(null);

    useEffect(() => {
        let alive = true;
        loadHelp(pageKey, currentLanguage()).then((h) => alive && setHelp(h)).catch(() => alive && setHelp(null));
        return () => { alive = false; };
    }, [pageKey]);

    useEffect(() => {
        if (!help || !section) return;
        const el = [...(body.current?.querySelectorAll("[data-section]") || [])].find((d) => d.dataset.section === section);
        el?.scrollIntoView({ block: "start" });
    }, [help, section]);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    const q = query.trim().toLowerCase();
    const sections = useMemo(() => (help?.sections || []).filter(
        (s) => !q || s.title.toLowerCase().includes(q) || s.body.toLowerCase().includes(q),
    ), [help, q]);

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="hlp-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer hlp-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <div className="hlp-kicker"><i className="fa-regular fa-circle-question" aria-hidden="true" /> {t("Help")}</div>
                        <h2 id="hlp-title">{help?.title || t("Help")}</h2>
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={t("Close")} onClick={onClose}>×</button>
                </header>
                <div className="bkm-drawer-body hlp-body" ref={body}>
                    {help === undefined && <div className="bkm-muted">{t("Loading…")}</div>}
                    {help === null && <div className="bkm-muted">{t("There is no help for this page yet.")}</div>}
                    {help && (
                        <>
                            <div className="hlp-summary"><Body text={help.summary} onNavigate={onClose} /></div>
                            <label className="hlp-search">
                                <i className="fa-solid fa-magnifying-glass" aria-hidden="true" />
                                <input type="search" value={query} onChange={(e) => setQuery(e.target.value)}
                                       placeholder={t("Search this help…")} aria-label={t("Search this help…")} />
                            </label>
                            {sections.length === 0 && <div className="bkm-muted">{t("Nothing in this help matches.")}</div>}
                            {sections.map((s) => (
                                <details key={s.title} className="hlp-section" data-section={s.title} open={Boolean(q) || Boolean(open[s.title])}
                                         onToggle={(e) => { const isOpen = e.currentTarget.open; if (!q) setOpen((o) => ({ ...o, [s.title]: isOpen })); }}>
                                    <summary><Marked text={s.title} q={q} /></summary>
                                    <div className="hlp-section-body"><Body text={s.body} onNavigate={onClose} q={q} /></div>
                                </details>
                            ))}
                        </>
                    )}
                </div>
            </aside>
        </div>
    );
}

/**
 * The header's help button, on pages that have help; "?" opens it too, and so does "?help=<section>"
 * in the address (a help result of the global search), open at that section.
 */
export function HelpButton({ pageKey }) {
    const [shown, setShown] = useState(false);
    const available = hasHelp(pageKey, currentLanguage());
    const location = useLocation();
    const navigate = useNavigate();
    const linked = new URLSearchParams(location.search).get("help");

    const close = () => {
        setShown(false);
        if (linked === null) return;
        const params = new URLSearchParams(location.search);
        params.delete("help");
        navigate({ search: params.toString() }, { replace: true });
    };

    useEffect(() => {
        if (!available) return undefined;
        const onKey = (e) => {
            const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
            if (e.key === "?" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); setShown(true); }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [available]);

    if (!available) return null;
    return (
        <>
            <button type="button" className="hlp-btn" onClick={() => setShown(true)}
                    aria-label={t("Help for this page")} title={t("Help for this page (?)")}>
                <i className="fa-solid fa-question" aria-hidden="true" />
            </button>
            {(shown || linked !== null) && (
                <HelpPanel key={`${pageKey}:${linked}`} pageKey={pageKey} section={linked} onClose={close} />
            )}
        </>
    );
}
