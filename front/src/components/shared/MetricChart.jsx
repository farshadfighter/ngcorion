// Small dependency-free SVG line chart for one metric's time series (as
// returned by GET /api/noc/hosts/:id/metrics). No charting library in this
// codebase yet, and one chart shape doesn't justify adding one - see
// TimeRangePicker.jsx for the picker that feeds this component its `points`.
const WIDTH = 640;
const HEIGHT = 160;
const PAD = { top: 10, right: 12, bottom: 22, left: 44 };

function formatAxisTime(iso) {
    const d = new Date(iso);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

export function MetricChart({
    points, color = "#1e3a5f", valueFormatter = (v) => v.toFixed(1),
    emptyLabel = "No data in this range yet", dark = false,
}) {
    const gridColor = dark ? "#1f2937" : "#eef0f4";
    const axisTextColor = dark ? "#5c667e" : "#9ca3af";
    const emptyBorderColor = dark ? "#1f2937" : "#e5e7eb";

    if (!points || points.length === 0) {
        return (
            <div style={{
                height: HEIGHT, display: "flex", alignItems: "center", justifyContent: "center",
                color: axisTextColor, fontSize: 12, border: `1px dashed ${emptyBorderColor}`, borderRadius: 8,
            }}>
                {emptyLabel}
            </div>
        );
    }

    const values = points.flatMap((p) => [p.min, p.max]);
    let minValue = Math.min(...values);
    let maxValue = Math.max(...values);
    // A flat line (e.g. a down interface at a steady 0 bytes) has
    // maxValue === minValue. Padding must go the same direction the real
    // data can move - for these always-non-negative metrics (bytes,
    // reachable) that's only upward, never below 0 (the old `|| 1`
    // fallback here padded downward unconditionally, so a flat 0 line drew
    // a nonsensical "-1 B" axis).
    if (maxValue === minValue) {
        const pad = maxValue !== 0 ? Math.abs(maxValue) * 0.2 : 1;
        maxValue += pad;
        if (minValue > 0) minValue = Math.max(0, minValue - pad);
    }
    const valueSpan = maxValue - minValue;

    const plotW = WIDTH - PAD.left - PAD.right;
    const plotH = HEIGHT - PAD.top - PAD.bottom;

    const times = points.map((p) => new Date(p.t).getTime());
    const minTime = times[0];
    const maxTime = times[times.length - 1] || minTime + 1;
    const timeSpan = maxTime - minTime || 1;

    const x = (t) => PAD.left + ((t - minTime) / timeSpan) * plotW;
    const y = (v) => PAD.top + plotH - ((v - minValue) / valueSpan) * plotH;

    const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(new Date(p.t).getTime())},${y(p.avg)}`).join(" ");
    const bandPath =
        points.map((p, i) => `${i === 0 ? "M" : "L"}${x(new Date(p.t).getTime())},${y(p.max)}`).join(" ") +
        " " +
        [...points].reverse().map((p) => `L${x(new Date(p.t).getTime())},${y(p.min)}`).join(" ") +
        " Z";

    const hasBand = points.some((p) => p.min !== p.max);

    return (
        <svg width="100%" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} style={{ display: "block" }}>
            {[0, 0.5, 1].map((f) => (
                <g key={f}>
                    <line
                        x1={PAD.left} x2={WIDTH - PAD.right}
                        y1={PAD.top + plotH * f} y2={PAD.top + plotH * f}
                        stroke={gridColor} strokeWidth={1}
                    />
                    <text x={PAD.left - 6} y={PAD.top + plotH * f + 3} textAnchor="end" fontSize={9} fill={axisTextColor}>
                        {valueFormatter(maxValue - valueSpan * f)}
                    </text>
                </g>
            ))}

            {hasBand && <path d={bandPath} fill={color} fillOpacity={0.12} stroke="none" />}
            <path d={linePath} fill="none" stroke={color} strokeWidth={1.75} />

            {[0, points.length - 1].map((i) => (
                <text
                    key={i}
                    x={x(new Date(points[i].t).getTime())}
                    y={HEIGHT - 6}
                    textAnchor={i === 0 ? "start" : "end"}
                    fontSize={9.5}
                    fill={axisTextColor}
                >
                    {formatAxisTime(points[i].t)}
                </text>
            ))}
        </svg>
    );
}

export default MetricChart;
