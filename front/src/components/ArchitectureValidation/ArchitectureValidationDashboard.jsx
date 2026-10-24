/**
 * Architecture Validation page: checks the topology against Cisco SAFE - segmentation between places in
 * the network, the Internet edge, the management network, redundant paths - and lists what it finds,
 * grouped by check, with what the topology shows (the unfiltered path, the link, the assets cut off).
 * A finding can be accepted, or ignored with a reason; "What is checked" lists every check.
 */
import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchFindings,
    fetchRules,
    runAnalysis,
    acceptFinding,
    ignoreFinding,
    clearMessages,
} from "../../store/architectureValidationSlice.jsx";
import "../../assets/ArchitectureValidation.css";
import { t, n } from "../../i18n";
import { tb, tv } from "../../i18n/backendText";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";
import { DOMAINS, DOMAIN_LABEL, PLACE_LABEL, countByDomain, evidenceText, groupByRule } from "./architectureFormat.js";

const STATUS_TABS = [
    { key: "open", label: t("Open") },
    { key: "accepted", label: t("Accepted") },
    { key: "ignored", label: t("Ignored") },
    { key: "", label: t("All") },
];

const EMPTY_TEXT = {
    open: t("No open findings. \"Run Analysis\" checks the topology against Cisco SAFE."),
    accepted: t("No accepted findings."),
    ignored: t("No ignored findings."),
    "": t("No findings. \"Run Analysis\" checks the topology against Cisco SAFE."),
};

const SEVERITY_CLASS = { low: "av-badge-low", medium: "av-badge-medium", high: "av-badge-high" };

const Chips = ({ rule }) => (
    <span className="av-chips">
        {rule.category && <span className="av-chip">{DOMAIN_LABEL[rule.category] || tv(rule.category)}</span>}
        {rule.place && <span className="av-chip av-chip-place">{PLACE_LABEL[rule.place] || rule.place}</span>}
    </span>
);

export const ArchitectureValidationDashboard = () => {
    const dispatch = useDispatch();
    const { findings, rules, isLoading, isAnalyzing, error, successMessage, lastRun } = useSelector(
        (state) => state.architectureValidation
    );
    const [view, setView] = useState("findings");
    const [statusFilter, setStatusFilter] = useState("open");
    const [ignoringId, setIgnoringId] = useState(null);
    const [ignoreReason, setIgnoreReason] = useState("");

    useEffect(() => { dispatch(fetchRules()); }, [dispatch]);

    useEffect(() => {
        dispatch(fetchFindings({ status: statusFilter || undefined }));
    }, [dispatch, statusFilter]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleAnalyze = () => {
        dispatch(runAnalysis()).then(() => dispatch(fetchFindings({ status: statusFilter || undefined })));
    };

    const handleIgnoreConfirm = () => {
        dispatch(ignoreFinding({ findingId: ignoringId, reason: ignoreReason || undefined }));
        setIgnoringId(null);
        setIgnoreReason("");
    };

    const groups = useMemo(() => groupByRule(findings, rules), [findings, rules]);
    const perDomain = useMemo(() => countByDomain(findings), [findings]);

    return (
        <div className="av-container">
            <div className="rep-shortcut-row"><ReportShortcut template="architecture" className="bkm-btn bkm-btn-sm" /></div>
            <p className="av-intro">
                {t("Checks the topology against Cisco SAFE: traffic between places of different trust (Internet, DMZ, users, guests, data center, management) passes a firewall, the edge and the paths to critical assets are redundant. Each asset's place comes from its network zone.")}
            </p>

            {statusFilter === "open" && view === "findings" && (
                <div className="av-domains">
                    {DOMAINS.map(([key, label]) => (
                        <div key={key} className={`av-domain ${perDomain[key] ? "av-domain-hit" : ""}`}>
                            <b>{n(perDomain[key])}</b><span>{label}</span>
                        </div>
                    ))}
                </div>
            )}

            <div className="av-toolbar">
                <div className="av-tabs">
                    <button className={`av-tab ${view === "findings" ? "active" : ""}`} onClick={() => setView("findings")}>
                        {t("Findings")}
                    </button>
                    <button className={`av-tab ${view === "rules" ? "active" : ""}`} onClick={() => setView("rules")}>
                        {t("What is checked")}
                    </button>
                </div>
                <div className="av-toolbar-actions">
                    {lastRun && (
                        <span className="av-last-run">
                            {t("Last run: {{findingCount}} finding(s) / {{assetCount}} asset(s)", { findingCount: lastRun.findingCount, assetCount: lastRun.assetCount })}
                        </span>
                    )}
                    <button className="av-btn av-btn-primary" onClick={handleAnalyze} disabled={isAnalyzing}>
                        <i className="fa-solid fa-diagram-project" /> {isAnalyzing ? t("Analyzing…") : t("Run Analysis")}
                    </button>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`av-toast ${error ? "av-toast-error" : "av-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            {view === "rules" ? (
                <div className="av-table-container av-scroll">
                    <table className="av-table">
                        <thead>
                            <tr>
                                <th>{t("Severity")}</th>
                                <th>{t("Check")}</th>
                                <th>{t("SAFE domain and place")}</th>
                                <th>{t("Recommendation")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.map((r) => (
                                <tr key={r.code}>
                                    <td><span className={`av-badge ${SEVERITY_CLASS[r.severity] || ""}`}>{tv(r.severity)}</span></td>
                                    <td>
                                        <div className="av-rule-code">{r.code}</div>
                                        <div className="av-rule-title">{tb(r.title)}</div>
                                    </td>
                                    <td><Chips rule={r} /></td>
                                    <td className="av-recommendation">{tb(r.recommendation)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : (
                <>
                    <div className="av-tabs av-status-tabs">
                        {STATUS_TABS.map((tab) => (
                            <button
                                key={tab.key}
                                className={`av-tab av-tab-sm ${statusFilter === tab.key ? "active" : ""}`}
                                onClick={() => setStatusFilter(tab.key)}
                            >
                                {tab.label}
                            </button>
                        ))}
                    </div>
                    {isLoading ? (
                        <div className="av-table-container"><div className="av-empty">{t("Loading findings…")}</div></div>
                    ) : groups.length === 0 ? (
                        <div className="av-table-container"><div className="av-empty">{EMPTY_TEXT[statusFilter]}</div></div>
                    ) : (
                        <div className="av-groups">
                            {groups.map(({ rule, findings: rows }) => (
                                <section key={rule.code} className="av-group">
                                    <header className="av-group-head">
                                        <span className={`av-badge ${SEVERITY_CLASS[rule.severity] || ""}`}>{tv(rule.severity)}</span>
                                        <span className="av-rule-code">{rule.code}</span>
                                        <h3 className="av-rule-title">{tb(rule.title)}</h3>
                                        <Chips rule={rule} />
                                        <span className="av-group-count">{t("{{total}} asset(s)", { total: n(rows.length) })}</span>
                                    </header>
                                    {rule.recommendation && <p className="av-recommendation">{tb(rule.recommendation)}</p>}
                                    <div className="av-scroll">
                                        <table className="av-table av-table-compact">
                                            <tbody>
                                                {rows.map((f) => (
                                                    <tr key={f.id}>
                                                        <td className="av-asset">{f.asset_name || "—"}</td>
                                                        <td className="av-evidence-cell">
                                                            {f.evidence ? (
                                                                <>
                                                                    {rule.evidence_label && <span className="av-evidence-label">{tb(rule.evidence_label)}</span>}
                                                                    <span className="av-evidence" dir="ltr">{evidenceText(f.evidence)}</span>
                                                                </>
                                                            ) : null}
                                                        </td>
                                                        <td className="av-row-end">
                                                            {f.status === "open" ? (
                                                                <div className="av-row-actions">
                                                                    <button className="av-link-btn" onClick={() => dispatch(acceptFinding(f.id))}>
                                                                        {t("Accept")}
                                                                    </button>
                                                                    <button className="av-link-btn av-link-btn-muted" onClick={() => setIgnoringId(f.id)}>
                                                                        {t("Ignore")}
                                                                    </button>
                                                                </div>
                                                            ) : (
                                                                <span className="av-decided" title={f.ignored_reason || ""}>
                                                                    {f.status === "accepted" ? t("Accepted") : t("Ignored")}
                                                                </span>
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </section>
                            ))}
                        </div>
                    )}
                </>
            )}

            {ignoringId !== null && (
                <div className="av-modal-backdrop" onClick={() => setIgnoringId(null)}>
                    <div className="av-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>{t("Ignore finding")}</h3>
                        <p className="av-modal-hint">{t("Optionally explain why this finding doesn't apply.")}</p>
                        <textarea
                            className="av-modal-textarea"
                            rows={3}
                            value={ignoreReason}
                            onChange={(e) => setIgnoreReason(e.target.value)}
                            placeholder={t("Reason (optional)")}
                        />
                        <div className="av-modal-actions">
                            <button className="av-btn" onClick={() => setIgnoringId(null)}>
                                {t("Cancel")}
                            </button>
                            <button className="av-btn av-btn-primary" onClick={handleIgnoreConfirm}>
                                {t("Ignore finding")}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ArchitectureValidationDashboard;
