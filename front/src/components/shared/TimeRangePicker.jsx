import { useState } from "react";

// Presets map straight to NocService.pick_granularity's tier boundaries
// (app/modules/noc/service.py) - 1h/6h stay in raw resolution, 24h/7d land
// on 5m rollups, 30d on 1h rollups. The caller never needs to know that; it
// just gets a {from, to} ISO pair back on every change.
const PRESETS = [
    { label: "1h", hours: 1 },
    { label: "6h", hours: 6 },
    { label: "24h", hours: 24 },
    { label: "7d", hours: 24 * 7 },
    { label: "30d", hours: 24 * 30 },
];

export function TimeRangePicker({ value, onChange }) {
    const [customOpen, setCustomOpen] = useState(false);
    const [customFrom, setCustomFrom] = useState("");
    const [customTo, setCustomTo] = useState("");

    const selectPreset = (hours, label) => {
        setCustomOpen(false);
        const to = new Date();
        const from = new Date(to.getTime() - hours * 3600 * 1000);
        onChange({ from: from.toISOString(), to: to.toISOString(), label });
    };

    const applyCustom = () => {
        if (!customFrom || !customTo) return;
        onChange({
            from: new Date(customFrom).toISOString(),
            to: new Date(customTo).toISOString(),
            label: "Custom",
        });
    };

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {PRESETS.map((p) => (
                    <button
                        key={p.label}
                        type="button"
                        onClick={() => selectPreset(p.hours, p.label)}
                        style={{
                            padding: "5px 11px", fontSize: 12, fontWeight: 600, borderRadius: 7, cursor: "pointer",
                            border: `1px solid ${value?.label === p.label ? "#1e3a5f" : "#e5e7eb"}`,
                            background: value?.label === p.label ? "#1e3a5f" : "#fff",
                            color: value?.label === p.label ? "#fff" : "#4b5563",
                        }}
                    >
                        {p.label}
                    </button>
                ))}
                <button
                    type="button"
                    onClick={() => setCustomOpen((v) => !v)}
                    style={{
                        padding: "5px 11px", fontSize: 12, fontWeight: 600, borderRadius: 7, cursor: "pointer",
                        border: `1px solid ${value?.label === "Custom" ? "#1e3a5f" : "#e5e7eb"}`,
                        background: value?.label === "Custom" ? "#1e3a5f" : "#fff",
                        color: value?.label === "Custom" ? "#fff" : "#4b5563",
                    }}
                >
                    Custom
                </button>
            </div>
            {customOpen && (
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <label style={{ display: "flex", flexDirection: "column", fontSize: 10.5, color: "#6b7280", gap: 2 }}>
                        From
                        <input type="datetime-local" value={customFrom} onChange={(e) => setCustomFrom(e.target.value)}
                            style={{ padding: "5px 7px", border: "1px solid #e5e7eb", borderRadius: 6, fontSize: 12 }} />
                    </label>
                    <label style={{ display: "flex", flexDirection: "column", fontSize: 10.5, color: "#6b7280", gap: 2 }}>
                        To
                        <input type="datetime-local" value={customTo} onChange={(e) => setCustomTo(e.target.value)}
                            style={{ padding: "5px 7px", border: "1px solid #e5e7eb", borderRadius: 6, fontSize: 12 }} />
                    </label>
                    <button type="button" onClick={applyCustom}
                        style={{ alignSelf: "flex-end", padding: "6px 12px", fontSize: 12, fontWeight: 600, borderRadius: 6, border: "1px solid #1e3a5f", background: "#1e3a5f", color: "#fff", cursor: "pointer" }}>
                        Apply
                    </button>
                </div>
            )}
        </div>
    );
}

export default TimeRangePicker;
