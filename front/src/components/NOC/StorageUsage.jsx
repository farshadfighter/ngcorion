import { formatBytes } from "../CVE/cveFormat";
import { usagePct, usageTone } from "./storageFormat";
import { n, t } from "../../i18n";
import "../../assets/Storage.css";

/**
 * How much of its disk budget a store (syslog messages, SNMP metrics) takes - measured on the stored rows,
 * so it falls when old data is removed (GET /api/noc/storage).
 */
export function StorageUsage({ label, used, budget, rows, rowsLabel }) {
    const pct = usagePct(used, budget);
    return (
        <div className="stg-usage">
            <div className="stg-head">
                <span className="stg-label">{label}</span>
                <span className="stg-figure">
                    {t("{{used}} of {{budget}}", { used: formatBytes(used), budget: formatBytes(budget) })}
                    {pct !== null && <b className={`stg-pct ${usageTone(pct)}`}>{n(`${pct}%`)}</b>}
                </span>
            </div>
            <div className="stg-bar" aria-hidden="true">
                <span className={usageTone(pct)} style={{ width: `${pct ?? 0}%` }} />
            </div>
            {rowsLabel && <span className="stg-sub">{rowsLabel(rows)}</span>}
        </div>
    );
}

export default StorageUsage;
