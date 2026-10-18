/**
 * The search box in the page header: assets (name, address, MAC, serial), CVE ids, unknown devices,
 * remediation findings, TLS certificates, software, asset groups, users, reports (GET /api/search, each
 * kind only with its read permission) and the menu's own pages.
 *
 * "/" or Ctrl+K focuses it from anywhere; ↑ ↓ choose, Enter opens, Esc closes. On a narrow screen it is an
 * icon that opens the box over the header.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";

import api from "../config/api.js";
import { n, t } from "../i18n";
import { tv } from "../i18n/backendText";
import { visibleMenu } from "./sidebarMenu";
import { itemTitle } from "./Remediation/remediationFormat.js";
import "../assets/GlobalSearch.css";

const KIND = {
    pages: t("Pages"),
    assets: t("Assets"),
    cves: t("Vulnerabilities (CVE)"),
    devices: t("Unknown devices"),
    findings: t("Remediation"),
    certificates: t("TLS certificates"),
    software: t("Software"),
    groups: t("Asset groups"),
    users: t("Users"),
    reports: t("Reports"),
};
const SEVERITY = { critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low") };
/** Persian and Arabic digits as ASCII ("۱۰.۲۰" -> "10.20"), as the server reads them too. */
const ascii = (s) => s.replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0)).replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660));

/** The second line of a result. */
function detailOf(kind, it) {
    switch (kind) {
        case "cves": return [it.severity && SEVERITY[it.severity], it.cvss != null && `CVSS ${n(it.cvss)}`, it.kev && "KEV"]
            .filter(Boolean).join(" · ");
        case "devices": return it.detail;
        case "findings": return [SEVERITY[it.severity], it.detail].filter(Boolean).join(" · ");
        case "software": return t("on {{count}} assets", { count: it.count });
        case "users": return [it.detail, tv(it.role)].filter(Boolean).join(" · ");
        default: return it.detail || "";
    }
}

export function GlobalSearch() {
    const navigate = useNavigate();
    const { role, permissions } = useSelector((s) => s.auth);
    const [q, setQ] = useState("");
    const [result, setResult] = useState({ query: "", groups: [] });
    const [open, setOpen] = useState(false);
    const [expanded, setExpanded] = useState(false);     // narrow screens
    const [active, setActive] = useState(0);
    const input = useRef(null);
    const box = useRef(null);
    const query = ascii(q).trim();

    // "/" or Ctrl+K: focus the box
    useEffect(() => {
        const onKey = (e) => {
            const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
            if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) {
                e.preventDefault();
                setExpanded(true);
                setTimeout(() => input.current?.focus(), 0);
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, []);

    // close on a click elsewhere
    useEffect(() => {
        const onDown = (e) => { if (box.current && !box.current.contains(e.target)) { setOpen(false); setExpanded(false); } };
        document.addEventListener("mousedown", onDown);
        return () => document.removeEventListener("mousedown", onDown);
    }, []);

    // the server, a moment after typing stops
    useEffect(() => {
        if (query.length < 2) return undefined;
        let alive = true;
        const timer = setTimeout(() => {
            api.get("/api/search", { params: { q: query, limit: 5 } })
                .then(({ data }) => alive && setResult(data)).catch(() => alive && setResult({ query, groups: [] }));
        }, 250);
        return () => { alive = false; clearTimeout(timer); };
    }, [query]);

    const pages = useMemo(() => {
        const needle = query.toLowerCase();
        if (!needle) return [];
        const menu = visibleMenu({ role, permissions });
        return [...menu.top, ...menu.groups.flatMap((g) => g.items.map((i) => ({ ...i, group: g.label })))]
            .filter((i) => i.label.toLowerCase().includes(needle) || (i.group || "").toLowerCase().includes(needle))
            .slice(0, 5)
            .map((i) => ({ title: i.label, detail: i.group || "", link: i.path }));
    }, [query, role, permissions]);

    const fresh = result.query === query && query.length >= 2;
    const groups = useMemo(() => [
        ...(pages.length ? [{ kind: "pages", items: pages }] : []),
        ...(fresh ? result.groups : []),
    ], [pages, fresh, result]);
    const flat = groups.flatMap((g) => g.items.map((it) => ({ kind: g.kind, it })));
    const current = Math.min(active, Math.max(flat.length - 1, 0));

    const go = (it) => {
        setOpen(false);
        setExpanded(false);
        setQ("");
        input.current?.blur();
        navigate(it.link);
    };
    const onKeyDown = (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); setActive((current + 1) % Math.max(flat.length, 1)); }
        else if (e.key === "ArrowUp") { e.preventDefault(); setActive((current - 1 + flat.length) % Math.max(flat.length, 1)); }
        else if (e.key === "Enter" && flat[current]) { e.preventDefault(); go(flat[current].it); }
        else if (e.key === "Escape") { setOpen(false); setExpanded(false); input.current?.blur(); }
    };

    const showPanel = open && query.length >= 1;
    const waiting = query.length >= 2 && !fresh;
    let index = -1;
    return (
        <div ref={box} className={`gs ${expanded ? "is-expanded" : ""}`}>
            <button type="button" className="gs-icon-btn" aria-label={t("Search")} onClick={() => { setExpanded(true); setTimeout(() => input.current?.focus(), 0); }}>
                <i className="fa-solid fa-magnifying-glass" aria-hidden="true" />
            </button>
            <label className="gs-box">
                <i className="fa-solid fa-magnifying-glass gs-glass" aria-hidden="true" />
                <input ref={input} value={q} type="search" role="combobox" aria-expanded={showPanel} aria-controls="gs-results"
                       aria-activedescendant={showPanel && flat.length ? `gs-opt-${current}` : undefined} aria-autocomplete="list"
                       placeholder={t("Search assets, IP, MAC, CVE, users…")} aria-label={t("Search everything")}
                       onChange={(e) => { setQ(e.target.value); setActive(0); setOpen(true); }}
                       onFocus={() => setOpen(true)} onKeyDown={onKeyDown} />
                <kbd className="gs-kbd" aria-hidden="true">/</kbd>
            </label>
            {showPanel && (
                <div className="gs-panel" id="gs-results" role="listbox" aria-label={t("Search results")}>
                    {query.length < 2 && !pages.length && <p className="gs-hint">{t("Type at least two letters or digits.")}</p>}
                    {groups.map((g) => (
                        <div key={g.kind} className="gs-group" role="group" aria-label={KIND[g.kind]}>
                            <div className="gs-group-title">{KIND[g.kind]}</div>
                            {g.items.map((it) => {
                                index += 1;
                                const i = index;
                                const title = g.kind === "findings" ? itemTitle(it) : it.title;
                                return (
                                    <div key={`${g.kind}-${it.id ?? it.link}`} id={`gs-opt-${i}`} role="option" aria-selected={i === current}
                                         className={`gs-item ${i === current ? "is-on" : ""}`}
                                         onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); go(it); }}>
                                        <bdi dir="auto" className="gs-title">{title}</bdi>
                                        {detailOf(g.kind, it) && <bdi dir="auto" className="gs-detail">{detailOf(g.kind, it)}</bdi>}
                                    </div>
                                );
                            })}
                        </div>
                    ))}
                    {waiting && <p className="gs-hint">{t("Searching…")}</p>}
                    {!waiting && query.length >= 2 && flat.length === 0 && <p className="gs-hint">{t("Nothing found for {{text}}", { text: query })}</p>}
                </div>
            )}
        </div>
    );
}
