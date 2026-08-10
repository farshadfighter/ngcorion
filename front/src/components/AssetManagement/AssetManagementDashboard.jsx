import React, { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import api from "../../config/api.js";
import { useAssetFormOptions } from "../AssetList/useAssetFormOptions";
import {
    PieChart, Pie, Cell, Tooltip,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer
} from "recharts";
import "../../assets/AssetManagementDashboard.css";

const COLORS = ["#1e3a5f", "#2d9cdb", "#27ae60", "#8e44ad", "#f39c12", "#e74c3c", "#16a085", "#d35400"];

const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
    if (percent < 0.05) return null;
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);
    return (
        <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={12} fontWeight={600}>
            {`${(percent * 100).toFixed(0)}%`}
        </text>
    );
};

export const AssetManagementDashboard = () => {
    const dispatch = useDispatch();
    const { assets, isLoading } = useSelector((state) => state.assets);
    // asset_inventory.risk_level is never written — the risk engine stores its
    // result in asset_risk_scores instead — so the critical count comes from the
    // risk module's own aggregate. null means "not available" (e.g. the user
    // lacks RISK read), which renders as a dash rather than a misleading 0.
    const [criticalCount, setCriticalCount] = useState(null);
    const { assetTypes } = useAssetFormOptions();

    useEffect(() => {
        dispatch(fetchAssets());
        // Critical count comes from the risk module's aggregate; best-effort, a
        // failure (or no RISK permission) leaves it null rather than showing 0.
        api.get("/api/risk/summary")
            .then((res) => {
                // A dev server answering an unproxied path returns index.html with
                // a 200, so check the shape rather than trusting the status code —
                // otherwise a missing endpoint silently reads as zero criticals.
                const rows = res.data?.by_risk_level;
                if (!Array.isArray(rows)) {
                    setCriticalCount(null);
                    return;
                }
                setCriticalCount(rows.find((r) => r.level === "critical")?.count ?? 0);
            })
            .catch(() => setCriticalCount(null));
    }, [dispatch]);

    const stats = useMemo(() => {
        if (!assets || assets.length === 0) return null;

        const now = new Date();
        const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);

        const total     = assets.length;
        const active    = assets.filter(a => a.status === "active").length;
        const inactive  = assets.filter(a => a.status !== "active").length;
        const newAssets = assets.filter(a => a.created_at && new Date(a.created_at) >= thirtyDaysAgo).length;
        const critical  = assets.filter(a => a.risk_level === "critical").length;

        // Asset Type chart — با resolve از assetTypes
        const typeMap = {};
        assets.forEach(a => {
            const assetType = assetTypes.find(t => t.id === a.asset_type_id);
            const key = assetType?.type_name || a.asset_type_name || "Unknown";
            typeMap[key] = (typeMap[key] || 0) + 1;
        });
        const typeData = Object.entries(typeMap)
            .filter(([k]) => k !== "Unknown")
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 8);

        // Vendor chart
        const vendorMap = {};
        assets.forEach(a => {
            const key = a.manufacturer || "Unknown";
            vendorMap[key] = (vendorMap[key] || 0) + 1;
        });
        const vendorData = Object.entries(vendorMap)
            .filter(([k]) => k !== "Unknown")
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 8);

        // OS chart
        const osMap = {};
        assets.forEach(a => {
            if (a.os_name) {
                osMap[a.os_name] = (osMap[a.os_name] || 0) + 1;
            }
        });
        const osData = Object.entries(osMap)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 6);

        return { total, active, inactive, newAssets, critical, typeData, vendorData, osData };
    }, [assets, assetTypes]);

    if (isLoading) {
        return (
            <div className="amd-loading">
                <div className="amd-spinner" />
                <p>Loading dashboard…</p>
            </div>
        );
    }

    const statCards = [
        { label: "Total Assets",        value: stats?.total     ?? 0, color: "#1e3a5f" },
        { label: "Active Assets",        value: stats?.active    ?? 0, color: "#27ae60" },
        { label: "Inactive Assets",      value: stats?.inactive  ?? 0, color: "#e74c3c" },
        { label: "New Assets (30 Days)", value: stats?.newAssets ?? 0, color: "#f39c12" },
        { label: "Critical Assets",      value: criticalCount ?? "—", color: "#8e44ad" },
    ];

    return (
        <div className="amd-container">
            <h1 className="amd-title">Asset Management Dashboard</h1>

            {/* ── کارت‌های آماری ── */}
            <div className="amd-stats-grid">
                {statCards.map((card) => (
                    <div key={card.label} className="amd-stat-card">
                        <div className="amd-stat-value" style={{ color: card.color }}>
                            {card.value}
                        </div>
                        <div className="amd-stat-label">{card.label}</div>
                    </div>
                ))}
            </div>

            {/* ── دو Pie Chart ── */}
            <div className="amd-charts-grid">

                {/* Asset Type */}
                <div className="amd-chart-card">
                    <h3 className="amd-chart-title">Asset Type</h3>
                    {stats?.typeData?.length > 0 ? (
                        <>
                            <ResponsiveContainer width="100%" height={200}>
                                <PieChart>
                                    <Pie
                                        data={stats.typeData}
                                        cx="50%" cy="50%"
                                        innerRadius={55} outerRadius={90}
                                        dataKey="value"
                                        labelLine={false}
                                        label={renderCustomLabel}
                                    >
                                        {stats.typeData.map((_, i) => (
                                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip formatter={(value, name) => [value, name]} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="amd-legend">
                                {stats.typeData.map((item, i) => (
                                    <div key={item.name} className="amd-legend-item">
                                        <div className="amd-legend-dot" style={{ background: COLORS[i % COLORS.length] }} />
                                        <span className="amd-legend-text">{item.name}: <strong>{item.value}</strong></span>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="amd-empty">No data</div>
                    )}
                </div>

                {/* Vendor */}
                <div className="amd-chart-card">
                    <h3 className="amd-chart-title">Vendor</h3>
                    {stats?.vendorData?.length > 0 ? (
                        <>
                            <ResponsiveContainer width="100%" height={200}>
                                <PieChart>
                                    <Pie
                                        data={stats.vendorData}
                                        cx="50%" cy="50%"
                                        innerRadius={55} outerRadius={90}
                                        dataKey="value"
                                        labelLine={false}
                                        label={renderCustomLabel}
                                    >
                                        {stats.vendorData.map((_, i) => (
                                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip formatter={(value, name) => [value, name]} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="amd-legend">
                                {stats.vendorData.map((item, i) => (
                                    <div key={item.name} className="amd-legend-item">
                                        <div className="amd-legend-dot" style={{ background: COLORS[i % COLORS.length] }} />
                                        <span className="amd-legend-text">{item.name}: <strong>{item.value}</strong></span>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="amd-empty">No data</div>
                    )}
                </div>
            </div>

            {/* ── Bar Chart OS ── */}
            <div className="amd-chart-card">
                <h3 className="amd-chart-title">Operating Systems</h3>
                {stats?.osData?.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={stats.osData} margin={{ top: 10, right: 20, left: 0, bottom: 40 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                            <XAxis dataKey="name" tick={{ fontSize: 12, fill: "#6b7280" }} angle={-20} textAnchor="end" interval={0} />
                            <YAxis tick={{ fontSize: 12, fill: "#6b7280" }} allowDecimals={false} />
                            <Tooltip />
                            <Bar dataKey="value" fill="#1e3a5f" radius={[6, 6, 0, 0]}
                                 label={{ position: "inside", fill: "white", fontSize: 12, fontWeight: 600 }} />
                        </BarChart>
                    </ResponsiveContainer>
                ) : (
                    <div className="amd-empty">No OS data available</div>
                )}
            </div>
        </div>
    );
};

export default AssetManagementDashboard;