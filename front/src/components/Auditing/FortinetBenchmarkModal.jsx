import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchFortinetBenchmark } from "../../store/auditSlice";

// Read-only viewer for the full CIS FortiGate Benchmark checklist (all 53
// controls), served from /api/audit/fortinet/benchmark. Lets an operator see
// every control — and how it is evaluated — without running an audit.

const typeBadgeStyle = (type) => ({
    display: "inline-block",
    padding: "2px 10px",
    borderRadius: "12px",
    fontSize: "12px",
    fontWeight: 600,
    background: type === "Automated" ? "#dbeafe" : "#fef3c7",
    color: type === "Automated" ? "#1e40af" : "#92400e",
    border: `1px solid ${type === "Automated" ? "#93c5fd" : "#fcd34d"}`,
    whiteSpace: "nowrap",
});

const chipStyle = (bg, fg, border) => ({
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    padding: "6px 14px",
    borderRadius: "10px",
    fontSize: "14px",
    fontWeight: 600,
    background: bg,
    color: fg,
    border: `1px solid ${border}`,
});

const thStyle = {
    textAlign: "left",
    padding: "8px 10px",
    fontSize: "12px",
    color: "#6b7280",
    borderBottom: "2px solid #e5e7eb",
    position: "sticky",
    top: 0,
    background: "#f9fafb",
    zIndex: 1,
};
const tdStyle = { padding: "8px 10px", fontSize: "13px", color: "#111827", borderBottom: "1px solid #f1f5f9", verticalAlign: "top" };
const codeStyle = { fontFamily: "monospace", fontSize: "12px", background: "#f3f4f6", padding: "1px 6px", borderRadius: "4px", whiteSpace: "nowrap" };

export const FortinetBenchmarkModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { data, isLoading, error } = useSelector((state) => state.audit.benchmark);

    const [query, setQuery] = useState("");
    const [typeFilter, setTypeFilter] = useState("all"); // all | Automated | Manual

    useEffect(() => {
        // Refetch only if we don't already have it cached.
        if (!data) dispatch(fetchFortinetBenchmark());
    }, [dispatch, data]);

    const controls = data?.controls || [];

    const filtered = useMemo(() => {
        const q = query.trim().toLowerCase();
        return controls.filter((c) => {
            if (typeFilter !== "all" && c.type !== typeFilter) return false;
            if (!q) return true;
            return (
                c.section.toLowerCase().includes(q) ||
                c.recommendation.toLowerCase().includes(q) ||
                c.control_id.toLowerCase().includes(q) ||
                (c.command || "").toLowerCase().includes(q)
            );
        });
    }, [controls, query, typeFilter]);

    // Preserve section order (controls arrive pre-sorted by section number).
    const groups = useMemo(() => {
        const out = [];
        const idx = {};
        for (const c of filtered) {
            const g = c.section_group || "Other";
            if (idx[g] === undefined) { idx[g] = out.length; out.push({ name: g, items: [] }); }
            out[idx[g]].items.push(c);
        }
        return out;
    }, [filtered]);

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: "white", borderRadius: "12px", width: "min(1100px, 95vw)",
                    maxHeight: "90vh", display: "flex", flexDirection: "column", overflow: "hidden",
                    boxShadow: "0 20px 60px rgba(0,0,0,0.25)",
                }}
            >
                {/* Header */}
                <div style={{ padding: "18px 22px", borderBottom: "1px solid #e5e7eb", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div>
                        <h2 style={{ margin: 0, fontSize: "18px", fontWeight: 700, color: "#111827" }}>
                            CIS FortiGate Benchmark — Audit Checklist
                        </h2>
                        <div style={{ fontSize: "13px", color: "#6b7280", marginTop: "2px" }}>
                            {data?.version || "CIS Fortinet FortiGate Benchmark"}
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        style={{ border: "none", background: "transparent", fontSize: "22px", cursor: "pointer", color: "#6b7280", lineHeight: 1 }}
                        aria-label="Close"
                    >
                        ✕
                    </button>
                </div>

                {/* Summary + filters */}
                <div style={{ padding: "14px 22px", borderBottom: "1px solid #f1f5f9", display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
                    <span style={chipStyle("#eef2ff", "#3730a3", "#c7d2fe")}>Total {data?.total ?? controls.length}</span>
                    <span style={chipStyle("#dbeafe", "#1e40af", "#93c5fd")}>Automated {data?.automated ?? "—"}</span>
                    <span style={chipStyle("#fef3c7", "#92400e", "#fcd34d")}>Manual {data?.manual ?? "—"}</span>

                    <div style={{ flex: 1 }} />

                    <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        style={{ padding: "7px 10px", borderRadius: "8px", border: "1px solid #d1d5db", fontSize: "13px" }}
                    >
                        <option value="all">All types</option>
                        <option value="Automated">Automated</option>
                        <option value="Manual">Manual</option>
                    </select>
                    <input
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search section, control, command…"
                        style={{ padding: "7px 12px", borderRadius: "8px", border: "1px solid #d1d5db", fontSize: "13px", width: "260px", maxWidth: "50vw" }}
                    />
                </div>

                {/* Body */}
                <div style={{ overflowY: "auto", padding: "8px 22px 22px" }}>
                    {isLoading && <div style={{ padding: "40px", textAlign: "center", color: "#6b7280" }}>Loading checklist…</div>}
                    {error && <div className="alert alert-error" style={{ marginTop: "12px" }}>{error}</div>}

                    {!isLoading && !error && groups.length === 0 && (
                        <div style={{ padding: "40px", textAlign: "center", color: "#6b7280" }}>No controls match your filter.</div>
                    )}

                    {!isLoading && !error && groups.map((group) => (
                        <div key={group.name} style={{ marginTop: "18px" }}>
                            <h3 style={{ fontSize: "14px", fontWeight: 700, color: "#374151", margin: "0 0 8px" }}>
                                {group.name}{" "}
                                <span style={{ fontWeight: 500, color: "#9ca3af" }}>({group.items.length})</span>
                            </h3>
                            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                                <thead>
                                    <tr>
                                        <th style={{ ...thStyle, width: "70px" }}>CIS §</th>
                                        <th style={thStyle}>Recommendation</th>
                                        <th style={{ ...thStyle, width: "110px" }}>Type</th>
                                        <th style={{ ...thStyle, width: "130px" }}>Scope</th>
                                        <th style={{ ...thStyle, width: "120px" }}>Control ID</th>
                                        <th style={thStyle}>Reads</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {group.items.map((c) => (
                                        <tr key={c.section}>
                                            <td style={{ ...tdStyle, fontWeight: 600 }}>{c.section}</td>
                                            <td style={tdStyle}>{c.recommendation}</td>
                                            <td style={tdStyle}><span style={typeBadgeStyle(c.type)}>{c.type}</span></td>
                                            <td style={tdStyle}>{c.scope}</td>
                                            <td style={tdStyle}><span style={codeStyle}>{c.control_id}</span></td>
                                            <td style={tdStyle}>{c.command ? <span style={codeStyle}>{c.command}</span> : "—"}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ))}
                </div>

                {/* Footer */}
                <div style={{ padding: "12px 22px", borderTop: "1px solid #e5e7eb", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", color: "#6b7280" }}>
                    <span>Automated = scored from configuration · Manual = evidence-only (not scored)</span>
                    <button className="btn-modal-secondary" onClick={onClose}>Close</button>
                </div>
            </div>
        </div>
    );
};

export default FortinetBenchmarkModal;
