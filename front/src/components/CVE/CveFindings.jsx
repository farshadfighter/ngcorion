import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchCveFindings, syncCveFromNvd, clearMessages } from "../../store/cveSlice.jsx";
import "../../assets/Cve.css";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_CLASS = {
    critical: "cve-badge-critical",
    high: "cve-badge-high",
    medium: "cve-badge-medium",
    low: "cve-badge-low",
};
const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"];

export const CveFindings = () => {
    const dispatch = useDispatch();
    const { summary, findings, isLoading, isSyncing, error, successMessage } = useSelector((state) => state.cve);

    const [severityFilter, setSeverityFilter] = useState("all");
    const [search, setSearch] = useState("");
    const [sortKey, setSortKey] = useState("severity");
    const [sortDir, setSortDir] = useState("asc");

    useEffect(() => {
        dispatch(fetchCveFindings());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 6000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleSync = () => {
        dispatch(syncCveFromNvd()).then(() => dispatch(fetchCveFindings()));
    };

    const handleSort = (key) => {
        if (sortKey === key) {
            setSortDir(sortDir === "asc" ? "desc" : "asc");
        } else {
            setSortKey(key);
            setSortDir("asc");
        }
    };

    const visibleFindings = useMemo(() => {
        let rows = findings;
        if (severityFilter !== "all") {
            rows = rows.filter((f) => (f.cve.severity || "").toLowerCase() === severityFilter);
        }
        if (search.trim()) {
            const q = search.trim().toLowerCase();
            rows = rows.filter(
                (f) =>
                    f.asset_name?.toLowerCase().includes(q) ||
                    f.cve.cve_id.toLowerCase().includes(q) ||
                    f.os_name?.toLowerCase().includes(q) ||
                    f.cve.product?.toLowerCase().includes(q)
            );
        }
        const sorted = [...rows].sort((a, b) => {
            let cmp = 0;
            if (sortKey === "severity") {
                cmp = (SEVERITY_ORDER[a.cve.severity] ?? 9) - (SEVERITY_ORDER[b.cve.severity] ?? 9);
            } else if (sortKey === "asset") {
                cmp = (a.asset_name || "").localeCompare(b.asset_name || "");
            } else if (sortKey === "cve_id") {
                cmp = a.cve.cve_id.localeCompare(b.cve.cve_id);
            } else if (sortKey === "cvss") {
                cmp = (a.cve.cvss_score ?? 0) - (b.cve.cvss_score ?? 0);
            }
            return sortDir === "asc" ? cmp : -cmp;
        });
        return sorted;
    }, [findings, severityFilter, search, sortKey, sortDir]);

    return (
        <div className="cve-container">
            <div className="cve-summary-cards">
                <div className="cve-card cve-card-total">
                    <span className="cve-card-value">{summary.total}</span>
                    <span className="cve-card-label">Total findings</span>
                </div>
                <div className="cve-card cve-card-critical">
                    <span className="cve-card-value">{summary.critical}</span>
                    <span className="cve-card-label">Critical</span>
                </div>
                <div className="cve-card cve-card-high">
                    <span className="cve-card-value">{summary.high}</span>
                    <span className="cve-card-label">High</span>
                </div>
                <div className="cve-card cve-card-medium">
                    <span className="cve-card-value">{summary.medium}</span>
                    <span className="cve-card-label">Medium</span>
                </div>
                <div className="cve-card cve-card-low">
                    <span className="cve-card-value">{summary.low}</span>
                    <span className="cve-card-label">Low</span>
                </div>
            </div>

            <div className="cve-toolbar">
                <div className="cve-tabs">
                    {SEVERITY_FILTERS.map((s) => (
                        <button
                            key={s}
                            className={`cve-tab ${severityFilter === s ? "active" : ""}`}
                            onClick={() => setSeverityFilter(s)}
                        >
                            {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
                        </button>
                    ))}
                </div>
                <div className="cve-toolbar-actions">
                    <input
                        className="cve-search"
                        placeholder="Search asset, CVE ID, product…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                    <button className="cve-btn cve-btn-primary" onClick={handleSync} disabled={isSyncing}>
                        <i className="fa-solid fa-rotate" /> {isSyncing ? "Syncing…" : "Sync from NVD"}
                    </button>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`cve-toast ${error ? "cve-toast-error" : "cve-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="cve-table-container">
                {isLoading ? (
                    <div className="cve-empty">Loading CVE findings…</div>
                ) : visibleFindings.length === 0 ? (
                    <div className="cve-empty">
                        {findings.length === 0
                            ? "No known vulnerabilities matched against your asset inventory. Assets need os_name/os_version recorded to be checked."
                            : "No findings match the current filter."}
                    </div>
                ) : (
                    <table className="cve-table">
                        <thead>
                            <tr>
                                <th className="cve-sortable" onClick={() => handleSort("severity")}>Severity</th>
                                <th className="cve-sortable" onClick={() => handleSort("cve_id")}>CVE ID</th>
                                <th className="cve-sortable" onClick={() => handleSort("asset")}>Asset</th>
                                <th>Product</th>
                                <th>Installed version</th>
                                <th>Fixed version</th>
                                <th className="cve-sortable" onClick={() => handleSort("cvss")}>CVSS</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {visibleFindings.map((f) => (
                                <tr key={`${f.asset_id}-${f.cve.id}`}>
                                    <td>
                                        <span className={`cve-badge ${SEVERITY_CLASS[f.cve.severity] || ""}`}>
                                            {f.cve.severity}
                                        </span>
                                    </td>
                                    <td>
                                        {f.cve.reference_url ? (
                                            <a href={f.cve.reference_url} target="_blank" rel="noreferrer" className="cve-link">
                                                {f.cve.cve_id}
                                            </a>
                                        ) : (
                                            f.cve.cve_id
                                        )}
                                    </td>
                                    <td className="cve-cell-strong">{f.asset_name || "—"}</td>
                                    <td>{f.cve.product}</td>
                                    <td>{f.os_version || "—"}</td>
                                    <td>{f.cve.fixed_version || "—"}</td>
                                    <td>{f.cve.cvss_score ?? "—"}</td>
                                    <td className="cve-cell-recommendation">{f.cve.recommendation || "—"}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default CveFindings;
