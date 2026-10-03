import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { SOURCE, errorText } from "./softwareFormat.js";

const pretty = (s) => (s || "").replace(/_/g, " ");

/**
 * Say what an unidentified product is in NVD (vendor:product), or that it is
 * internal software NVD does not know. Applies to every asset.
 */
export function MapModal({ product, onClose, onSaved }) {
    const [query, setQuery] = useState(product.label.replace(/[-_.]+/g, " "));
    const [suggestions, setSuggestions] = useState(null);
    const [choice, setChoice] = useState(null);           // "vendor:product" | "internal" | "manual"
    const [manual, setManual] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const searchRef = useRef(null);

    useEffect(() => { searchRef.current?.focus(); }, []);

    useEffect(() => {
        const q = query.trim();
        let alive = true;
        const timer = setTimeout(() => {
            if (q.length < 2) { setSuggestions([]); return; }
            api.get("/api/software/suggest", { params: { q } })
                .then(({ data }) => alive && setSuggestions(data))
                .catch(() => alive && setSuggestions([]));
        }, 250);
        return () => { alive = false; clearTimeout(timer); };
    }, [query]);

    const manualOk = /^[a-z0-9_.\-\\+!~/()%]+:[a-z0-9_.\-\\+!~/()%]+$/i.test(manual.trim());
    const valid = choice === "internal" || (choice === "manual" ? manualOk : !!choice);

    const save = () => {
        let body;
        if (choice === "internal") body = { status: "internal" };
        else {
            const [vendor, prod] = (choice === "manual" ? manual.trim() : choice).toLowerCase().split(":");
            body = { status: "cpe", vendor, product: prod };
        }
        setBusy(true);
        setError(null);
        api.put("/api/software/maps", { match_key: product.key, label: null, ...body })
            .then(() => onSaved())
            .catch((e) => setError(errorText(e, t("Could not save"))))
            .finally(() => setBusy(false));
    };

    const versions = product.versions.map((v) => v.version).filter(Boolean).slice(0, 3);
    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sw-map-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal sw-modal">
                <h2 id="sw-map-title">{t("Identify “{{name}}”", { name: product.label })}</h2>
                <p className="alr-hint">
                    {t("To be matched against NVD, the product needs the name NVD gives it (its CPE). Your choice applies to every asset.")}
                </p>
                <p className="sw-facts">
                    {t("{{count}} assets", { count: product.asset_count })}
                    {versions.length > 0 && <> · <span className="sw-ltr-inline">{versions.join(", ")}</span></>}
                    {" · "}{product.sources.map((s) => SOURCE[s]?.label || s).join(", ")}
                    {product.origins.length > 0 && <> · <span className="sw-ltr-inline">{product.origins.join(", ")}</span></>}
                </p>

                <label className="bkm-search sw-map-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)}
                           aria-label={t("Search the CVE database")} placeholder={t("Search the CVE database")} />
                </label>

                <div className="rem-radio sw-options" role="radiogroup" aria-label={t("What this product is")}>
                    {(suggestions || []).map((s, i) => {
                        const value = `${s.vendor}:${s.product}`;
                        return (
                            <button key={value} type="button" role="radio" aria-checked={choice === value}
                                    className={choice === value ? "is-on" : ""} onClick={() => setChoice(value)}>
                                <span className="sw-opt-row">
                                    <span className="sw-cpe">{value}</span>
                                    {i === 0 && <span className="sw-opt-tag">{t("closest name")}</span>}
                                </span>
                                <small>{pretty(s.product)} · {pretty(s.vendor)} · {t("{{count}} CVEs in the local database", { count: s.cves })}</small>
                            </button>
                        );
                    })}
                    {suggestions && suggestions.length === 0 && query.trim().length >= 2 && (
                        <p className="alr-hint">{t("No product with that name in the local CVE database.")}</p>
                    )}
                    <button type="button" role="radio" aria-checked={choice === "internal"}
                            className={choice === "internal" ? "is-on" : ""} onClick={() => setChoice("internal")}>
                        {t("It is our own software, not in NVD")}
                        <small>{t("It is no longer shown as unidentified")}</small>
                    </button>
                    <button type="button" role="radio" aria-checked={choice === "manual"}
                            className={choice === "manual" ? "is-on" : ""} onClick={() => setChoice("manual")}>
                        {t("Enter it myself")}
                        <small>{t("Vendor and product the way NVD writes them, e.g. vendor:product")}</small>
                    </button>
                    {choice === "manual" && (
                        <input className="bkm-select sw-ltr" value={manual} maxLength={280} autoFocus
                               onChange={(e) => setManual(e.target.value)} placeholder="vendor:product"
                               aria-label={t("Vendor and product")} />
                    )}
                </div>

                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !valid} onClick={save}>
                        {busy ? t("Saving…") : t("Save for every asset")}
                    </button>
                </div>
            </div>
        </div>
    );
}
