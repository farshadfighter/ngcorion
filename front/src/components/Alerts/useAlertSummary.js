import { useCallback, useEffect, useState } from "react";
import api from "../../config/api.js";

const POLL_MS = 30000;

/**
 * Counts and latest alerts for the header bell and the sidebar badge.
 * Refreshes every 30 s, when the tab comes back into view, and when a page
 * announces a change (acknowledge, resolve).
 */
export function useAlertSummary(enabled = true) {
    const [summary, setSummary] = useState(null);
    const [tick, setTick] = useState(0);
    const refresh = useCallback(() => setTick((n) => n + 1), []);

    useEffect(() => {
        if (!enabled) return undefined;
        let alive = true;
        api.get("/api/alerts/summary")
            .then(({ data }) => { if (alive) setSummary(data); })
            .catch(() => {});
        return () => { alive = false; };
    }, [enabled, tick]);

    useEffect(() => {
        if (!enabled) return undefined;
        const timer = setInterval(() => {
            if (document.visibilityState === "visible") refresh();
        }, POLL_MS);
        const onVisible = () => document.visibilityState === "visible" && refresh();
        window.addEventListener("alerts:changed", refresh);
        document.addEventListener("visibilitychange", onVisible);
        return () => {
            clearInterval(timer);
            window.removeEventListener("alerts:changed", refresh);
            document.removeEventListener("visibilitychange", onVisible);
        };
    }, [enabled, refresh]);

    return { summary, refresh };
}
