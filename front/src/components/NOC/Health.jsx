/**
 * Device health on the NOC host page: CPU, memory, disk and temperature from the last poll, the
 * file systems and temperature sensors behind them, uptime and the restarts NOC noticed
 * (GET /api/noc/hosts/:id). The host list uses HealthBar for its compact columns.
 */
import { n, t } from "../../i18n";
import { formatDateTime } from "../../utils/dates.js";
import { SOURCE_LABELS, bytes, celsius, duration, level, pct } from "./healthFormat.js";
import "../../assets/Noc.css";

export function HealthBar({ value, compact = false }) {
    if (value == null) return <span className="noc-hb-none">—</span>;
    const width = Math.max(2, Math.min(100, value));
    return (
        <span className={`noc-hb ${compact ? "noc-hb-compact" : ""}`}>
            <span className="noc-hb-track" aria-hidden="true">
                <span className={`noc-hb-fill noc-hb-${level(value)}`} style={{ width: `${width}%` }} />
            </span>
            <span className="noc-hb-value">{pct(value)}</span>
        </span>
    );
}

function Tile({ label, value, sub, bar, tempLevel }) {
    return (
        <div className={`noc-ht ${tempLevel ? `noc-ht-${tempLevel}` : ""}`}>
            <span className="noc-ht-label">{label}</span>
            <b className="noc-ht-value">{value}</b>
            {bar !== undefined && (
                <span className="noc-hb-track noc-ht-track" aria-hidden="true">
                    {bar != null && <span className={`noc-hb-fill noc-hb-${level(bar)}`} style={{ width: `${Math.max(2, Math.min(100, bar))}%` }} />}
                </span>
            )}
            {sub && <span className="noc-ht-sub">{sub}</span>}
        </div>
    );
}

export function HealthCard({ host }) {
    const h = host.health || {};
    const nothing = [h.cpu_percent, h.memory_percent, h.disk_percent, h.temperature_c].every((v) => v == null);
    const fullest = host.filesystems?.[0];
    const hottest = host.sensors?.[0];
    return (
        <div className="noc-card">
            <div className="noc-card-head">
                <h3>{t("Device health")}</h3>
                {host.health_source && <span className="noc-faint">{t("From {{source}}", { source: SOURCE_LABELS[host.health_source] || host.health_source })}</span>}
            </div>
            {!host.reachable && !nothing && (
                <p className="noc-note">{t("The device does not answer now; these are the last values it reported.")}</p>
            )}
            {nothing ? (
                <div className="noc-empty">
                    {host.credential
                        ? t("No health data yet. The device must expose HOST-RESOURCES-MIB, net-snmp's UCD-SNMP-MIB, or the Cisco or FortiGate MIBs over SNMP.")
                        : t("Configure an SNMP credential to start collecting this.")}
                </div>
            ) : (
                <div className="noc-ht-grid">
                    <Tile label={t("CPU")} value={pct(h.cpu_percent)} bar={h.cpu_percent} />
                    <Tile label={t("Memory")} value={pct(h.memory_percent)} bar={h.memory_percent}
                          sub={host.memory_total_bytes ? t("of {{total}}", { total: bytes(host.memory_total_bytes) }) : null} />
                    <Tile label={t("Disk")} value={pct(h.disk_percent)} bar={h.disk_percent}
                          sub={fullest ? <bdi dir="ltr">{fullest.name}</bdi> : null} />
                    <Tile label={t("Temperature")} value={celsius(h.temperature_c)}
                          tempLevel={h.temperature_c == null ? null : level(h.temperature_c, 60, 70)}
                          sub={hottest ? <bdi dir="ltr">{hottest.name}</bdi> : null} />
                </div>
            )}
            <dl className="noc-kv-grid noc-ht-kv">
                <dt>{t("Uptime")}</dt><dd>{host.reachable ? duration(host.uptime_seconds) : "—"}</dd>
                <dt>{t("Up since")}</dt><dd>{host.booted_at ? formatDateTime(host.booted_at) : "—"}</dd>
            </dl>

            {host.filesystems?.length > 0 && (
                <>
                    <h4 className="noc-h4">{t("File systems")}</h4>
                    <table className="noc-table noc-table-compact">
                        <thead><tr><th>{t("Mount / name")}</th><th>{t("Used")}</th><th>{t("Size")}</th><th>{t("Usage")}</th></tr></thead>
                        <tbody>
                            {host.filesystems.slice(0, 8).map((f) => (
                                <tr key={f.name}>
                                    <td dir="ltr" className="noc-mono">{f.name}</td>
                                    <td>{bytes(f.used)}</td>
                                    <td>{bytes(f.size)}</td>
                                    <td><HealthBar value={f.percent} compact /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </>
            )}
            {host.sensors?.length > 0 && (
                <>
                    <h4 className="noc-h4">{t("Temperature sensors")}</h4>
                    <ul className="noc-sensors">
                        {host.sensors.slice(0, 8).map((s) => (
                            <li key={s.name} className={`noc-sensor noc-ht-${level(s.celsius, 60, 70)}`}>
                                <bdi dir="ltr">{s.name}</bdi><b>{celsius(s.celsius)}</b>
                            </li>
                        ))}
                    </ul>
                </>
            )}
        </div>
    );
}

export function RebootsCard({ reboots }) {
    return (
        <div className="noc-card">
            <h3>{t("Restarts")}</h3>
            {!reboots?.length ? (
                <div className="noc-empty">{t("No restart noticed. NOC notices one when the device's uptime starts again from zero.")}</div>
            ) : (
                <table className="noc-table noc-table-compact">
                    <thead><tr><th>{t("Came up at")}</th><th>{t("Uptime before it")}</th><th>{t("Noticed")}</th></tr></thead>
                    <tbody>
                        {reboots.map((r) => (
                            <tr key={r.detected_at}>
                                <td>{formatDateTime(r.booted_at)}</td>
                                <td>{duration(r.previous_uptime_seconds)}</td>
                                <td className="noc-faint">{formatDateTime(r.detected_at)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
            {reboots?.length > 0 && <p className="noc-faint noc-small">{t("{{value}} restarts listed (the last 20).", { value: n(reboots.length) })}</p>}
        </div>
    );
}
