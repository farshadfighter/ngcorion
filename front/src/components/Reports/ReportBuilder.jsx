import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import api from "../../config/api.js";
import { currentLanguage, t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { CLASSIFICATIONS, PERIODS, SCOPES, label, errorText } from "./reportFormat.js";
import { ScheduleModal } from "./ScheduleModal.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Reports.css";

function Seg({ value, options, onChange, name }) {
    return (
        <div className="rep-seg" role="group" aria-label={name}>
            {options.map(([v, l]) => (
                <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>{l}</button>
            ))}
        </div>
    );
}

const SCOPE_LIST = { types: "types", sites: "sites", owners: "owners", zones: "zones", assets: "assets" };

/** One report: period, assets, sections, options, language, format, classification. */
export function ReportBuilder() {
    const { template: templateId } = useParams();
    const [params] = useSearchParams();
    const navigate = useNavigate();
    const [catalog, setCatalog] = useState(null);
    const [scopeOptions, setScopeOptions] = useState(null);
    const [form, setForm] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(null);
    const [scheduling, setScheduling] = useState(false);

    const tpl = catalog?.templates.find((x) => x.id === templateId);

    useEffect(() => {
        Promise.all([api.get("/api/reports/catalog"), api.get("/api/reports/scope-options")])
            .then(([c, s]) => {
                setCatalog(c.data);
                setScopeOptions(s.data);
                const found = c.data.templates.find((x) => x.id === templateId && x.available);
                if (!found) return;
                // Options can arrive from the page that sent the person here (?sources=cve, ?kev_only=1).
                const options = Object.fromEntries(found.options.map((o) => {
                    const q = params.get(o.key);
                    if (q == null) return [o.key, o.default];
                    if (o.kind === "bool") return [o.key, q === "1" || q === "true"];
                    if (o.kind === "multi") return [o.key, q.split(",").filter(Boolean)];
                    return [o.key, q];
                }));
                setForm({
                    title: "", preset: found.default_period, from: "", to: "", compare: true,
                    scopeMode: "all", scopeValues: [],
                    sections: found.sections.filter((s) => s.default && s.allowed).map((s) => s.key),
                    options, language: currentLanguage() === "fa" ? "fa" : "en", formats: ["pdf"],
                    classification: c.data.default_classification || "internal", orientation: "portrait",
                });
                if (params.get("schedule") === "1") setScheduling(true);
            })
            .catch(() => setError(t("Could not load the report")));
        // The query string is read once when the page opens.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [templateId]);

    const set = (patch) => setForm((f) => ({ ...f, ...patch }));
    const toggle = (list, v) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

    const assetCount = useMemo(() => {
        if (!scopeOptions || !form) return null;
        return form.scopeMode === "all" ? scopeOptions.total : null;
    }, [scopeOptions, form]);

    const request = () => ({
        template: templateId, title: form.title.trim() || null, language: form.language, formats: form.formats,
        classification: form.classification,
        params: {
            period: form.preset === "custom" ? { preset: "custom", from: form.from, to: form.to } : { preset: form.preset },
            compare: form.compare, scope: { mode: form.scopeMode, values: form.scopeValues },
            sections: form.sections, options: form.options, orientation: form.orientation,
        },
    });

    const valid = form && form.sections.length > 0 && form.formats.length > 0
        && (form.scopeMode === "all" || form.scopeValues.length > 0)
        && (form.preset !== "custom" || (form.from && form.to));

    const build = () => {
        setBusy("build");
        setError(null);
        api.post("/api/reports", request())
            .then(({ data }) => navigate(`/reports/archive?new=${data.id}`))
            .catch((e) => { setError(errorText(e, t("Could not start the report"))); setBusy(null); });
    };

    const preview = () => {
        setBusy("preview");
        setError(null);
        api.post("/api/reports/preview", request(), { responseType: "blob" })
            .then(({ data }) => {
                const url = URL.createObjectURL(data);
                window.open(url, "_blank", "noopener");
                setTimeout(() => URL.revokeObjectURL(url), 60000);
            })
            .catch(async (e) => {
                let text = t("Could not build the preview");
                try { text = errorText({ response: { data: JSON.parse(await e.response.data.text()) } }, text); } catch { /* not JSON */ }
                setError(text);
            })
            .finally(() => setBusy(null));
    };

    if (error && !form) return <div className="bkm-page"><div className="bkm-note bkm-note-error" role="alert">{error}</div></div>;
    if (catalog && !tpl?.available) {
        return <div className="bkm-page"><div className="bkm-empty"><b>{t("This report is not available yet")}</b>
            <Link className="bkm-link" to="/reports">{t("Back to reports")}</Link></div></div>;
    }
    if (!form) return <div className="bkm-page"><div className="bkm-muted">{t("Loading…")}</div></div>;

    const list = SCOPE_LIST[form.scopeMode] ? scopeOptions[SCOPE_LIST[form.scopeMode]] : [];
    const sectionTitle = (k) => tb(tpl.sections.find((s) => s.key === k)?.title);
    const excelOnly = tpl.sections.some((s) => s.excel_only && form.sections.includes(s.key));

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <div className="bkm-crumb"><Link to="/reports">{t("Reports")}</Link> › {tb(tpl.title)}</div>
                    <h1>{t("Build report: {{name}}", { name: tb(tpl.title) })}</h1>
                    <p>{tb(tpl.description)}</p>
                </div>
            </div>

            <div className="rep-builder">
                <section className="bkm-card bkm-pad rep-form">
                    <fieldset className="rep-fs">
                        <legend>{t("Title")}</legend>
                        <input type="text" className="bkm-select" value={form.title} maxLength={200}
                               placeholder={tb(tpl.title)} onChange={(e) => set({ title: e.target.value })} aria-label={t("Title")} />
                    </fieldset>

                    <fieldset className="rep-fs">
                        <legend>{t("Period")}</legend>
                        <div className="bkm-chips">
                            {PERIODS.map(([v, l]) => (
                                <button key={v} type="button" aria-pressed={form.preset === v}
                                        className={`bkm-chip ${form.preset === v ? "is-on" : ""}`} onClick={() => set({ preset: v })}>{l}</button>
                            ))}
                        </div>
                        {form.preset === "custom" && (
                            <div className="rep-grid-2">
                                <label className="alr-lbl">{t("From")}
                                    <input type="date" className="bkm-select" value={form.from} onChange={(e) => set({ from: e.target.value })} /></label>
                                <label className="alr-lbl">{t("To")}
                                    <input type="date" className="bkm-select" value={form.to} onChange={(e) => set({ to: e.target.value })} /></label>
                            </div>
                        )}
                        <label className={`rep-check ${form.compare ? "is-on" : ""}`}>
                            <input type="checkbox" checked={form.compare} onChange={(e) => set({ compare: e.target.checked })} />
                            <span>{t("Compare with the previous period")}<small>{t("Every figure shows its change since the period before.")}</small></span>
                        </label>
                        <p className="alr-hint">{form.language === "fa"
                            ? t("Months, quarters and years follow the Solar Hijri calendar because the report is in Persian.")
                            : t("Months, quarters and years follow the Gregorian calendar because the report is in English.")}</p>
                    </fieldset>

                    <fieldset className="rep-fs">
                        <legend>{t("Assets")}</legend>
                        <div className="bkm-chips">
                            {SCOPES.map(([v, l]) => (
                                <button key={v} type="button" aria-pressed={form.scopeMode === v}
                                        className={`bkm-chip ${form.scopeMode === v ? "is-on" : ""}`}
                                        onClick={() => set({ scopeMode: v, scopeValues: [] })}>
                                    {l}{v === "all" ? <b>{n(scopeOptions.total)}</b> : null}
                                </button>
                            ))}
                        </div>
                        {form.scopeMode !== "all" && (
                            list.length
                                ? <div className="rep-picks">{list.map((o) => (
                                    <button key={o.id} type="button" aria-pressed={form.scopeValues.includes(o.id)}
                                            className={`bkm-chip ${form.scopeValues.includes(o.id) ? "is-on" : ""}`}
                                            onClick={() => set({ scopeValues: toggle(form.scopeValues, o.id) })}>
                                        <span className="bidi-auto">{o.name}</span>
                                    </button>
                                ))}</div>
                                : <p className="alr-hint">{t("Nothing to choose from yet.")}</p>
                        )}
                    </fieldset>

                    <fieldset className="rep-fs">
                        <legend>{t("Sections")}</legend>
                        <div className="rep-checks">
                            {tpl.sections.map((s) => {
                                const on = form.sections.includes(s.key);
                                return (
                                    <label key={s.key} className={`rep-check ${on ? "is-on" : ""} ${s.allowed ? "" : "is-off"}`}
                                           title={s.allowed ? undefined : t("You have no access to the module this section comes from")}>
                                        <input type="checkbox" checked={on} disabled={!s.allowed}
                                               onChange={() => set({ sections: toggle(form.sections, s.key) })} />
                                        <span>{tb(s.title)}{(s.hint || !s.allowed) && (
                                            <small>{s.allowed ? tb(s.hint) : t("No access")}</small>)}</span>
                                    </label>
                                );
                            })}
                        </div>
                    </fieldset>

                    {tpl.options.length > 0 && (
                        <fieldset className="rep-fs">
                            <legend>{t("Options")}</legend>
                            {tpl.options.map((o) => (
                                o.kind === "bool" ? (
                                    <label key={o.key} className={`rep-check ${form.options[o.key] ? "is-on" : ""}`}>
                                        <input type="checkbox" checked={!!form.options[o.key]}
                                               onChange={(e) => set({ options: { ...form.options, [o.key]: e.target.checked } })} />
                                        <span>{tb(o.label)}</span>
                                    </label>
                                ) : o.kind === "choice" ? (
                                    <label key={o.key} className="alr-lbl">{tb(o.label)}
                                        <select className="bkm-select" value={form.options[o.key]}
                                                onChange={(e) => set({ options: { ...form.options, [o.key]: e.target.value } })}>
                                            {o.choices.map((c) => <option key={c.value} value={c.value}>{tb(c.label)}</option>)}
                                        </select>
                                    </label>
                                ) : (
                                    <div key={o.key} className="alr-lbl">{tb(o.label)}
                                        <div className="bkm-chips">
                                            {o.choices.map((c) => {
                                                const on = (form.options[o.key] || []).includes(c.value);
                                                return (
                                                    <button key={c.value} type="button" aria-pressed={on}
                                                            className={`bkm-chip ${on ? "is-on" : ""}`}
                                                            onClick={() => set({ options: { ...form.options, [o.key]: toggle(form.options[o.key] || [], c.value) } })}>
                                                        {tb(c.label)}
                                                    </button>
                                                );
                                            })}
                                        </div>
                                        <span className="alr-hint">{t("None chosen means all of them.")}</span>
                                    </div>
                                )
                            ))}
                        </fieldset>
                    )}

                    <div className="rep-grid-2">
                        <fieldset className="rep-fs">
                            <legend>{t("Report language")}</legend>
                            <Seg name={t("Report language")} value={form.language} onChange={(v) => set({ language: v })}
                                 options={[["fa", t("Persian · Solar Hijri dates")], ["en", t("English · Gregorian dates")]]} />
                        </fieldset>
                        <fieldset className="rep-fs">
                            <legend>{t("File format")}</legend>
                            <Seg name={t("File format")} value={form.formats.join("+")}
                                 onChange={(v) => set({ formats: v.split("+") })}
                                 options={[["pdf", "PDF"], ["xlsx", "Excel"], ["pdf+xlsx", t("Both")]]} />
                            {excelOnly && !form.formats.includes("xlsx") && (
                                <span className="alr-hint">{t("An Excel file is added for the appendix.")}</span>
                            )}
                        </fieldset>
                        <fieldset className="rep-fs">
                            <legend>{t("Classification")}</legend>
                            <Seg name={t("Classification")} value={form.classification} onChange={(v) => set({ classification: v })}
                                 options={CLASSIFICATIONS} />
                        </fieldset>
                        <fieldset className="rep-fs">
                            <legend>{t("Page orientation")}</legend>
                            <Seg name={t("Page orientation")} value={form.orientation} onChange={(v) => set({ orientation: v })}
                                 options={[["portrait", t("Portrait (A4)")], ["landscape", t("Landscape")]]} />
                        </fieldset>
                    </div>
                </section>

                <aside className="bkm-card bkm-pad rep-summary">
                    <h2 className="bkm-h3">{t("What will be built")}</h2>
                    <dl>
                        <dt>{t("Report")}</dt><dd>{tb(tpl.title)}</dd>
                        <dt>{t("Period")}</dt><dd>{form.preset === "custom" && form.from && form.to ? `${form.from} – ${form.to}` : label(PERIODS, form.preset)}
                            {form.compare ? ` · ${t("compared")}` : ""}</dd>
                        <dt>{t("Assets")}</dt><dd>{assetCount != null ? t("{{count}} assets", { count: assetCount })
                            : t("{{count}} chosen", { count: form.scopeValues.length })}</dd>
                        <dt>{t("Sections")}</dt><dd>{form.sections.length ? form.sections.map(sectionTitle).join(currentLanguage() === "fa" ? "، " : ", ") : "—"}</dd>
                        <dt>{t("Output")}</dt><dd>{form.formats.map((f) => (f === "pdf" ? "PDF" : "Excel")).join(" + ")} · {form.language === "fa" ? t("Persian") : t("English")}</dd>
                        <dt>{t("Classification")}</dt><dd>{label(CLASSIFICATIONS, form.classification)}</dd>
                    </dl>
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    <div className="rep-stack">
                        <button type="button" className="bkm-btn bkm-btn-primary" disabled={!valid || !!busy} onClick={build}>
                            {busy === "build" ? t("Starting…") : t("Build report")}</button>
                        <button type="button" className="bkm-btn" disabled={!valid || !!busy} onClick={preview}>
                            {busy === "preview" ? t("Building the preview…") : t("Preview PDF")}</button>
                        <button type="button" className="bkm-btn" disabled={!valid || !!busy || form.preset === "custom"}
                                title={form.preset === "custom" ? t("A schedule needs a period that moves with it, not fixed dates") : undefined}
                                onClick={() => setScheduling(true)}>{t("Save as a schedule…")}</button>
                    </div>
                    <p className="rep-info">{t("The report is built in the background; you can leave this page. It appears in the archive when it is ready.")}</p>
                    <p className="rep-info">{t("Only data you are allowed to read goes into the report. A section you cannot read is left out, with a line saying so.")}</p>
                </aside>
            </div>

            {scheduling && (
                <ScheduleModal draft={request()} templateTitle={tpl.title} onClose={() => setScheduling(false)}
                               onSaved={() => navigate("/reports/schedules")} />
            )}
        </div>
    );
}
