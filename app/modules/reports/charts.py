"""
Charts drawn as SVG for the PDF. One scale per chart places the line, the
grid lines and the labels, so every label names a value the chart reaches.
Charts read left to right (time runs left to right in both languages).
"""
from html import escape
from typing import List, Optional, Sequence, Tuple

INK = "#1b2333"
MUTED = "#5d6a80"
GRID = "#e6ebf2"
NAVY = "#1e3a5f"

SEVERITY_COLORS = {"critical": "#c0262d", "high": "#e0671b", "medium": "#d9a514", "low": "#9aa6b8"}


def _nice_bounds(values: Sequence[float], floor: float = 0, ceil: float = 100) -> Tuple[float, float, float]:
    lo, hi = min(values), max(values)
    if hi - lo < 10:
        mid = (hi + lo) / 2
        lo, hi = mid - 5, mid + 5
    step = 10 if hi - lo <= 40 else 20
    lo = max(floor, (int(lo) // step) * step)
    hi = min(ceil, -(-int(hi) // step) * step)
    if hi <= lo:
        hi = lo + step
    return lo, hi, step


def line(points: List[Tuple[str, Optional[float]]], fmt, label_every: int = 4, width: int = 480,
         height: int = 136, floor: float = 0, ceil: float = 100) -> Tuple[str, List[Tuple[float, str, str]]]:
    """points: [(x label, value or None)] oldest first. fmt formats a number for the axis.

    Returns the SVG and the x-axis labels as (left %, text, anchor). The labels
    are laid out in HTML under the chart: the PDF engine does not shape
    Persian text inside SVG, so month names would come out broken there."""
    known = [(i, v) for i, (_, v) in enumerate(points) if v is not None]
    if len(known) < 2:
        return "", []
    lo, hi, step = _nice_bounds([v for _, v in known], floor, ceil)
    x0, x1, y0, y1 = 34, width - 10, height - 10, 10
    n = len(points) - 1 or 1

    def X(i):
        return x0 + (x1 - x0) * i / n

    def Y(v):
        return y0 - (y0 - y1) * (v - lo) / (hi - lo)

    parts = []
    t = lo
    while t <= hi + 1e-9:
        parts.append(f'<line x1="{x0}" x2="{x1}" y1="{Y(t):.1f}" y2="{Y(t):.1f}" stroke="{GRID}" stroke-width="1"/>'
                     f'<text x="{x0 - 6}" y="{Y(t) + 3:.1f}" text-anchor="end">{escape(fmt(t))}</text>')
        t += step
    pts = " ".join(f"{X(i):.1f},{Y(v):.1f}" for i, v in known)
    parts.append(f'<polygon points="{X(known[0][0]):.1f},{y0} {pts} {X(known[-1][0]):.1f},{y0}" '
                 f'fill="{NAVY}" fill-opacity="0.08"/>')
    parts.append(f'<polyline points="{pts}" fill="none" stroke="{NAVY}" stroke-width="2" stroke-linejoin="round"/>')
    labels = []
    for i, (label, _) in enumerate(points):
        if i % label_every == 0 or i == len(points) - 1:
            if i != len(points) - 1 and len(points) - 1 - i < label_every / 2:
                continue        # too close to the last label
            anchor = "end" if i == len(points) - 1 else ("start" if i == 0 else "middle")
            labels.append((100 * X(i) / width, label, anchor))
    fi, fv = known[0]
    li, lv = known[-1]
    parts.append(f'<circle cx="{X(fi):.1f}" cy="{Y(fv):.1f}" r="2.5" fill="#ffffff" stroke="{NAVY}" stroke-width="1.5"/>'
                 f'<text x="{X(fi) + 6:.1f}" y="{Y(fv) - 6:.1f}">{escape(fmt(fv))}</text>')
    parts.append(f'<circle cx="{X(li):.1f}" cy="{Y(lv):.1f}" r="3.5" fill="{NAVY}"/>'
                 f'<text x="{X(li) - 6:.1f}" y="{Y(lv) - 7:.1f}" text-anchor="end" fill="{INK}" '
                 f'font-weight="700">{escape(fmt(lv))}</text>')
    svg = (f'<svg viewBox="0 0 {width} {height}" width="100%" xmlns="http://www.w3.org/2000/svg" '
           f'class="chart" font-family="RVazir, RVazirLatin, sans-serif" font-size="8" fill="{MUTED}">'
           f'{"".join(parts)}</svg>')
    return svg, labels
