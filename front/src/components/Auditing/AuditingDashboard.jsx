import React, { useMemo } from "react";
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, LabelList,
} from "recharts";
import "../../assets/AuditingDashboard.css";

// ============================================================
// MOCK DATA — وقتی backend آماده شد اینجا رو جایگزین کن
// ============================================================
const MOCK = {
    // Findings By Severity
    findingsBySeverity: [
        { name: "Critical", value: 5,  color: "#ef4444" },
        { name: "High",     value: 16, color: "#f97316" },
        { name: "Medium",   value: 10, color: "#22c55e" },
        { name: "Low",      value: 20, color: "#14b8a6" },
    ],

    // Top Failed Controls
    topFailedControls: [
        { name: "Password Policy",    value: 5,  color: "#facc15" },
        { name: "SNMP Security",      value: 5,  color: "#8b5cf6" },
        { name: "NTP Configuration",  value: 16, color: "#22c55e" },
        { name: "Syslog Config",      value: 16, color: "#3b82f6" },
        { name: "SSH Hardening",      value: 16, color: "#1e3a5f" },
    ],

    // Compliance Trend — روزانه
    complianceTrend: [
        { date: "2/1",  value: 71 }, { date: "2/2",  value: 77 },
        { date: "2/3",  value: 52 }, { date: "2/4",  value: 62 },
        { date: "2/5",  value: 80 }, { date: "2/6",  value: 84 },
        { date: "2/7",  value: 88 }, { date: "2/8",  value: 94 },
        { date: "2/9",  value: 71 }, { date: "2/10", value: 77 },
        { date: "2/11", value: 52 }, { date: "2/12", value: 62 },
        { date: "2/13", value: 80 }, { date: "2/14", value: 84 },
        { date: "2/15", value: 88 }, { date: "2/16", value: 71 },
        { date: "2/17", value: 77 }, { date: "2/18", value: 52 },
        { date: "2/19", value: 62 }, { date: "2/20", value: 80 },
        { date: "2/21", value: 84 }, { date: "2/22", value: 88 },
        { date: "2/23", value: 94 }, { date: "2/24", value: 71 },
        { date: "2/25", value: 77 }, { date: "2/26", value: 52 },
        { date: "2/27", value: 62 }, { date: "2/28", value: 80 },
        { date: "3/1",  value: 84 }, { date: "3/2",  value: 88 },
    ],

    // Remediation Progress
    remediation: {
        openFindings:   3284,
        fixedThisMonth: 642,
        resolved:       "19%",
    },

    // Compliance By Asset Type
    complianceByType: [
        { name: "Firewall", value: 92 },
        { name: "Switch",   value: 82 },
        { name: "Windows",  value: 71 },
        { name: "Linux",    value: 78 },
        { name: "F5",       value: 90 },
    ],

    // Summary Cards
    summary: {
        complianceScore:       "84%",
        auditedAssets:         2145,
        failedControls:        3284,
        criticalFindings:      147,
        assetsOutOfCompliance: 342,
    },

    // Critical Findings Table
    criticalFindings: [
        { asset: "DC01",    finding: "SMBv1",  severity: "critical" },
        { asset: "FW-Core", finding: "SMBv1",  severity: "high"     },
        { asset: "FW-Core", finding: "SMBv1",  severity: "high"     },
        { asset: "FW-Core", finding: "SMBv1",  severity: "medium"   },
        { asset: "FW-Core", finding: "SMBv1",  severity: "medium"   },
        { asset: "FW-Core", finding: "SMBv1",  severity: "low"      },
        { asset: "FW-Core", finding: "SMBv1",  severity: "low"      },
        { asset: "FW-Core", finding: "SMBv1",  severity: "critical" },
        { asset: "FW-Core", finding: "SMBv1",  severity: "high"     },
        { asset: "FW-Core", finding: "SMBv1",  severity: "medium"   },
    ],

    // Audit Coverage
    coverage: {
        total:      2400,
        audited:    2145,
        notAudited: 255,
    },
};
// ============================================================

// ── Custom label برای Pie ────────────────────────────────────
const renderPieLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
    if (percent < 0.05) return null;
    const RADIAN = Math.PI / 180;
    const r = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + r * Math.cos(-midAngle * RADIAN);
    const y = cy + r * Math.sin(-midAngle * RADIAN);
    return (
        <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>
            {`${(percent * 100).toFixed(0)}%`}
        </text>
    );
};

// ── StatCard مشترک ───────────────────────────────────────────
const StatCard = ({ label, value }) => (
    <div className="aud-stat-card">
        <div className="aud-stat-card-label">{label}</div>
        <div className="aud-stat-card-value">{value}</div>
    </div>
);

// ============================================================
// کامپوننت اصلی
// ============================================================
export const AuditingDashboard = () => {
    const data = MOCK; // ← وقتی backend آماده شد این رو با useSelector جایگزین کن

    const coveragePercent = Math.round((data.coverage.audited / data.coverage.total) * 100);

    return (
        <div className="aud-container">

            {/* ── ردیف اول: دو Pie Chart ── */}
            <div className="aud-row aud-row-2">

                {/* Findings By Severity */}
                <div className="aud-card">
                    <div className="aud-card-title">Findings By Severity</div>
                    <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                            <Pie data={data.findingsBySeverity} cx="50%" cy="50%"
                                 innerRadius={50} outerRadius={80}
                                 dataKey="value" labelLine={false} label={renderPieLabel}>
                                {data.findingsBySeverity.map((entry, i) => (
                                    <Cell key={i} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip formatter={(v, n) => [v, n]} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="aud-legend">
                        {data.findingsBySeverity.map((item) => (
                            <div key={item.name} className="aud-legend-item">
                                <div className="aud-legend-dot" style={{ background: item.color }} />
                                <span>{item.name}: <strong>{item.value}</strong></span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Top Failed Controls */}
                <div className="aud-card">
                    <div className="aud-card-title">Top Failed Controls</div>
                    <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                            <Pie data={data.topFailedControls} cx="50%" cy="50%"
                                 innerRadius={50} outerRadius={80}
                                 dataKey="value" labelLine={false} label={renderPieLabel}>
                                {data.topFailedControls.map((entry, i) => (
                                    <Cell key={i} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip formatter={(v, n) => [v, n]} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="aud-legend">
                        {data.topFailedControls.map((item) => (
                            <div key={item.name} className="aud-legend-item">
                                <div className="aud-legend-dot" style={{ background: item.color }} />
                                <span>{item.name}: <strong>{item.value}</strong></span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* ── Compliance Trend ── */}
            <div className="aud-trend-card">
                <div className="aud-card-title">Compliance Trend</div>
                <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={data.complianceTrend} margin={{ top: 20, right: 10, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                        <XAxis dataKey="date" tick={{ fontSize: 11, fill: "#6b7280" }} />
                        <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} domain={[0, 100]} />
                        <Tooltip formatter={(v) => [`${v}%`, "Compliance"]} />
                        <Bar dataKey="value" fill="#1e3a5f" radius={[3, 3, 0, 0]}>
                            <LabelList dataKey="value" position="top" fontSize={10} fill="#6b7280" formatter={(v) => `${v}%`} />
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            </div>

            {/* ── Remediation Progress ── */}
            <div className="aud-remediation-card">
                <div className="aud-card-title">Remediation Progress</div>
                <div className="aud-stat-cards">
                    <StatCard label="Open Findings"    value={data.remediation.openFindings} />
                    <StatCard label="Fixed This Month" value={data.remediation.fixedThisMonth} />
                    <StatCard label="Resolved"         value={data.remediation.resolved} />
                </div>
            </div>

            {/* ── ردیف: Compliance By Asset Type + Critical Findings Table ── */}
            <div className="aud-row aud-row-2">

                {/* Compliance By Asset Type */}
                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                    <div className="aud-card">
                        <div className="aud-card-title">Compliance By Asset Type</div>
                        {data.complianceByType.map((item) => (
                            <div key={item.name} className="aud-progress-bar-wrapper">
                                <div className="aud-progress-label">
                                    <span>{item.name}</span>
                                    <span style={{ color: "#1e3a5f", fontWeight: 600 }}>{item.value}%</span>
                                </div>
                                <div className="aud-progress-track">
                                    <div className="aud-progress-fill" style={{ width: `${item.value}%` }} />
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Summary Cards */}
                    <div className="aud-card">
                        <div className="aud-card-title">Compliance By Asset Type</div>
                        <div className="aud-summary-cards">
                            <StatCard label="Compliance Score"       value={data.summary.complianceScore} />
                            <StatCard label="Audited Assets"         value={data.summary.auditedAssets} />
                            <StatCard label="Failed Controls"        value={data.summary.failedControls} />
                            <StatCard label="Critical Findings"      value={data.summary.criticalFindings} />
                            <StatCard label="Assets Out Of Compliance" value={data.summary.assetsOutOfCompliance} />
                        </div>
                    </div>
                </div>

                {/* Critical Findings Table */}
                <div className="aud-table-card">
                    <div className="aud-table-header">Critical Findings Table</div>
                    <table className="aud-table">
                        <thead>
                        <tr>
                            <th>Asset</th>
                            <th>Finding</th>
                            <th>Severity</th>
                        </tr>
                        </thead>
                        <tbody>
                        {data.criticalFindings.map((row, i) => (
                            <tr key={i}>
                                <td>{row.asset}</td>
                                <td>{row.finding}</td>
                                <td>
                                        <span className={`aud-severity ${row.severity}`}>
                                            {row.severity}
                                        </span>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* ── Audit Coverage ── */}
            <div className="aud-coverage-card">
                <div className="aud-card-title">Audit Coverage</div>
                <div className="aud-coverage-inner">
                    <div className="aud-coverage-total-label">Total Assets</div>
                    <div className="aud-coverage-total-value">{data.coverage.total.toLocaleString()}</div>
                    <div className="aud-coverage-track">
                        <div className="aud-coverage-fill" style={{ width: `${coveragePercent}%` }} />
                    </div>
                    <div className="aud-coverage-legend">
                        <div className="aud-coverage-legend-item">
                            <div className="aud-coverage-dot" style={{ background: "#1e3a5f" }} />
                            <span>Audited: <strong>{data.coverage.audited.toLocaleString()}</strong></span>
                        </div>
                        <div className="aud-coverage-legend-item">
                            <div className="aud-coverage-dot" style={{ background: "#e5e7eb" }} />
                            <span>Not Audited: <strong>{data.coverage.notAudited.toLocaleString()}</strong></span>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    );
};

export default AuditingDashboard;