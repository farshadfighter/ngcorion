import React, { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    Cell, LabelList,
} from "recharts";
import api from "../../config/api.js";
import { fetchAuditSessions } from "../../store/auditSlice";
import { getDeviceName } from "../../store/hardeningSlice";
import { fetchAuditDashboard } from "../../store/auditDashboardSlice";
import { FindingsBySeverity } from "./dashboard/FindingsBySeverity";
import { TopFailedControls } from "./dashboard/TopFailedControls";
import { ComplianceTrend } from "./dashboard/ComplianceTrend";
import "../../assets/AuditingDashboard.css";

// ── Compliance badge colours: green >= 80, yellow 50-79, red < 50 ──────────────
const scoreColor = (p) => (p >= 80 ? "#16a34a" : p >= 50 ? "#d97706" : "#dc2626");
const scoreBg    = (p) => (p >= 80 ? "#dcfce7" : p >= 50 ? "#fef3c7" : "#fee2e2");

// Collapse the granular device_type / sub_device_type to a display family.
const familyOf = (dt) => {
    if (!dt) return "unknown";
    const d = dt.toLowerCase();
    if (d.startsWith("linux")) return "linux";
    if (d.startsWith("windows")) return "windows";
    if (d.startsWith("mssql")) return "mssql";
    return d; // cisco / fortinet / apache / mongodb
};

const compliancePct = (s) =>
    Math.round(s?.compliance?.compliance_pct ?? s?.compliance_pct ?? 0);

const ComplianceBadge = ({ pct }) => (
    <span
        style={{
            display: "inline-block",
            padding: "2px 10px",
            borderRadius: "12px",
            fontSize: "12px",
            fontWeight: 700,
            color: scoreColor(pct),
            background: scoreBg(pct),
            minWidth: "48px",
            textAlign: "center",
        }}
    >
        {pct}%
    </span>
);

const StatCard = ({ label, value }) => (
    <div className="aud-stat-card">
        <div className="aud-stat-card-label">{label}</div>
        <div className="aud-stat-card-value">{value}</div>
    </div>
);

const fmtDate = (d) => {
    if (!d) return "Never";
    const dt = new Date(d);
    return isNaN(dt.getTime()) ? "-" : dt.toLocaleString();
};

export const AuditingDashboard = () => {
    const dispatch = useDispatch();
    const { sessions, isLoading } = useSelector((state) => state.audit);
    // Aggregates the sessions list cannot answer on its own (per-severity
    // findings, per-control failures, month-by-month trend).
    const { severity, topFailed, trend, overview, remediation, critical } = useSelector(
        (state) => state.auditDashboard
    );
    const [assets, setAssets] = useState([]);

    useEffect(() => {
        dispatch(fetchAuditSessions({ limit: 200, offset: 0 }));
        dispatch(fetchAuditDashboard());
        // Total-asset coverage: best-effort, tolerate failure.
        api.get("/api/assets/")
            .then((res) => setAssets(Array.isArray(res.data) ? res.data : []))
            .catch(() => setAssets([]));
    }, [dispatch]);

    // ── Latest session per asset (prefer completed, else most recent) ──────────
    const latestByAsset = useMemo(() => {
        const map = new Map();
        (sessions || []).forEach((s) => {
            const key = s.asset_id ?? s.asset_name ?? s.session_id;
            const prev = map.get(key);
            const ts = new Date(s.started_at || 0).getTime();
            if (!prev) { map.set(key, s); return; }
            const prevCompleted = prev.status === "completed";
            const curCompleted = s.status === "completed";
            const prevTs = new Date(prev.started_at || 0).getTime();
            // Completed sessions win; among equals, the most recent wins.
            if ((curCompleted && !prevCompleted) ||
                (curCompleted === prevCompleted && ts > prevTs)) {
                map.set(key, s);
            }
        });
        return map;
    }, [sessions]);

    // ── Per-asset rows (audited), sorted worst-first ──────────────────────────
    const assetRows = useMemo(() => {
        const rows = [...latestByAsset.values()]
            .filter((s) => s.status === "completed")
            .map((s) => ({
                key: s.session_id,
                asset: s.asset_name || `Asset ${s.asset_id ?? "?"}`,
                family: familyOf(s.sub_device_type || s.device_type),
                deviceLabel: getDeviceName(s.sub_device_type || s.device_type),
                pct: compliancePct(s),
                total: s.compliance?.total_checks ?? s.compliance?.total ?? 0,
                failed: s.compliance?.failed ?? s.compliance?.failed_checks ?? 0,
                date: s.started_at,
            }));
        return rows.sort((a, b) => a.pct - b.pct);
    }, [latestByAsset]);

    // ── Breakdown by OS / service type ────────────────────────────────────────
    const byType = useMemo(() => {
        const agg = {};
        assetRows.forEach((r) => {
            if (!agg[r.family]) agg[r.family] = { sum: 0, count: 0, failed: 0 };
            agg[r.family].sum += r.pct;
            agg[r.family].count += 1;
            agg[r.family].failed += r.failed;
        });
        return Object.entries(agg).map(([family, v]) => ({
            name: getDeviceName(family),
            family,
            value: Math.round(v.sum / v.count),
            count: v.count,
        })).sort((a, b) => b.value - a.value);
    }, [assetRows]);

    // ── Summary metrics ───────────────────────────────────────────────────────
    const summary = useMemo(() => {
        const audited = assetRows.length;
        const avg = audited
            ? Math.round(assetRows.reduce((s, r) => s + r.pct, 0) / audited)
            : 0;
        const outOfCompliance = assetRows.filter((r) => r.pct < 80).length;
        const failedControls = assetRows.reduce((s, r) => s + (r.failed || 0), 0);
        return { audited, avg, outOfCompliance, failedControls };
    }, [assetRows]);

    // ── Coverage: audited vs total known assets ──────────────────────────────
    const totalAssets = assets.length || summary.audited;
    const coveragePercent = totalAssets
        ? Math.round((summary.audited / totalAssets) * 100)
        : 0;
    const notAudited = Math.max(totalAssets - summary.audited, 0);

    if (isLoading && assetRows.length === 0) {
        return (
            <div className="aud-container">
                <div className="aud-card">
                    <div className="loading-spinner">Loading compliance data…</div>
                </div>
            </div>
        );
    }

    return (
        <div className="aud-container">

            {/* ── Findings breakdown (aggregate endpoints) ── */}
            <div className="aud-row aud-row-2">
                <FindingsBySeverity items={severity?.items} />
                <TopFailedControls items={topFailed?.items} />
            </div>

            <ComplianceTrend points={trend?.points} message={trend?.message} />

            {/* ── Remediation progress ── */}
            <div className="aud-card">
                <div className="aud-card-title">Remediation Progress</div>
                <div className="aud-summary-cards">
                    <StatCard label="Open Findings" value={remediation?.open_findings ?? "—"} />
                    <StatCard label="Fixed This Month" value={remediation?.fixed_this_month ?? "—"} />
                    <StatCard
                        label="Resolved"
                        value={
                            remediation?.resolved_percent === undefined
                                ? "—"
                                : `${remediation.resolved_percent}%`
                        }
                    />
                </div>
            </div>

            {/* ── Compliance by device type + coverage ── */}
            <div className="aud-row aud-row-2">
                <div className="aud-card">
                    <div className="aud-card-title">Compliance By OS / Service Type</div>
                    {byType.length === 0 ? (
                        <div className="aud-empty">No completed audits yet.</div>
                    ) : (
                        <>
                            <ResponsiveContainer width="100%" height={200}>
                                <BarChart data={byType} margin={{ top: 20, right: 10, left: -20, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                                    <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#6b7280" }} interval={0} angle={-12} textAnchor="end" height={50} />
                                    <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} domain={[0, 100]} />
                                    <Tooltip formatter={(v, _n, p) => [`${v}% (${p.payload.count} asset(s))`, "Compliance"]} />
                                    <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                                        <LabelList dataKey="value" position="top" fontSize={10} fill="#6b7280" formatter={(v) => `${v}%`} />
                                        {byType.map((entry) => (
                                            <Cell key={entry.family} fill={scoreColor(entry.value)} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                            {byType.map((item) => (
                                <div key={item.family} className="aud-progress-bar-wrapper">
                                    <div className="aud-progress-label">
                                        <span>{item.name} <span style={{ color: "#9ca3af" }}>({item.count})</span></span>
                                        <span style={{ color: scoreColor(item.value), fontWeight: 700 }}>{item.value}%</span>
                                    </div>
                                    <div className="aud-progress-track">
                                        <div className="aud-progress-fill" style={{ width: `${item.value}%`, background: scoreColor(item.value) }} />
                                    </div>
                                </div>
                            ))}
                        </>
                    )}
                </div>

                {/* Audit coverage */}
                <div className="aud-coverage-card">
                    <div className="aud-card-title">Audit Coverage</div>
                    <div className="aud-coverage-inner">
                        <div className="aud-coverage-total-label">Total Assets</div>
                        <div className="aud-coverage-total-value">{totalAssets.toLocaleString()}</div>
                        <div className="aud-coverage-track">
                            <div className="aud-coverage-fill" style={{ width: `${coveragePercent}%` }} />
                        </div>
                        <div className="aud-coverage-legend">
                            <div className="aud-coverage-legend-item">
                                <div className="aud-coverage-dot" style={{ background: "#1e3a5f" }} />
                                <span>Audited: <strong>{summary.audited.toLocaleString()}</strong></span>
                            </div>
                            <div className="aud-coverage-legend-item">
                                <div className="aud-coverage-dot" style={{ background: "#e5e7eb" }} />
                                <span>Not Audited: <strong>{notAudited.toLocaleString()}</strong></span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* ── Executive summary + critical findings ── */}
            <div className="aud-row aud-row-2">
                <div className="aud-card">
                    <div className="aud-card-title">Executive Summary</div>
                    <div className="aud-summary-cards">
                        <StatCard
                            label="Compliance Score"
                            value={
                                overview?.average_compliance === undefined
                                    ? "—"
                                    : `${overview.average_compliance}%`
                            }
                        />
                        <StatCard label="Audited Assets" value={overview?.audited_assets ?? "—"} />
                        <StatCard label="Failed Controls" value={overview?.failed_checks ?? "—"} />
                        <StatCard
                            label="Critical Findings"
                            value={critical?.items?.length ?? "—"}
                        />
                        <StatCard
                            label="Assets Out Of Compliance"
                            value={summary.outOfCompliance}
                        />
                    </div>
                </div>

                <div className="aud-card">
                    <div className="aud-card-title">Critical Findings Table</div>
                    {(critical?.items || []).length === 0 ? (
                        <div className="aud-empty">No unresolved critical findings.</div>
                    ) : (
                        <div className="aud-table-wrapper">
                            <table className="aud-table">
                                <thead>
                                    <tr>
                                        <th>Asset</th>
                                        <th>Finding</th>
                                        <th>Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {critical.items.map((f) => (
                                        <tr key={f.id}>
                                            <td>{f.asset_name || "-"}</td>
                                            <td title={f.check_title || ""}>{f.check_number}</td>
                                            <td>
                                                <span className={`aud-severity ${String(f.severity || "").toLowerCase()}`}>
                                                    {f.severity || "-"}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* ── Summary cards ── */}
            <div className="aud-card">
                <div className="aud-card-title">Compliance Overview</div>
                <div className="aud-summary-cards">
                    <StatCard label="Average Compliance" value={`${summary.avg}%`} />
                    <StatCard label="Audited Assets" value={summary.audited} />
                    <StatCard label="Assets Out Of Compliance (<80%)" value={summary.outOfCompliance} />
                    <StatCard label="Failed Controls" value={summary.failedControls} />
                    <StatCard label="Total Known Assets" value={totalAssets} />
                </div>
            </div>

            {/* ── Per-asset compliance table ── */}
            <div className="aud-table-card">
                <div className="aud-table-header">Per-Asset Compliance</div>
                <div className="aud-table-wrapper">
                    <table className="aud-table">
                        <thead>
                            <tr>
                                <th>Asset</th>
                                <th>OS / Service</th>
                                <th>Compliance</th>
                                <th>Checks</th>
                                <th>Last Audit</th>
                            </tr>
                        </thead>
                        <tbody>
                            {assetRows.length === 0 ? (
                                <tr>
                                    <td colSpan={5} style={{ textAlign: "center", padding: "32px", color: "#6b7280" }}>
                                        No completed audits yet. Run an audit to populate the dashboard.
                                    </td>
                                </tr>
                            ) : (
                                assetRows.map((r) => (
                                    <tr key={r.key}>
                                        <td>{r.asset}</td>
                                        <td>{r.deviceLabel}</td>
                                        <td><ComplianceBadge pct={r.pct} /></td>
                                        <td>{r.total ? `${r.total - r.failed}/${r.total} passed` : "-"}</td>
                                        <td>{fmtDate(r.date)}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    );
};

export default AuditingDashboard;
