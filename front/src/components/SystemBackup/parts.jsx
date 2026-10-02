import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { backupStep } from "./format.js";

// Pieces shared by the backups table and the backup drawer.

export function Health({ b }) {
    if (b.status === "queued" || b.status === "running") {
        return (
            <>
                <span className="bkm-pill bkm-pill-run">{b.status === "queued" ? t("Waiting to start") : t("Being written")}</span>
                <div className="rep-prog"><i style={{ width: `${Math.max(b.progress, 8)}%` }} /></div>
                <span className="bkm-sub">{backupStep(b.step)}</span>
            </>
        );
    }
    if (b.status === "failed") return <><span className="bkm-pill bkm-pill-bad">{t("Failed")}</span><span className="bkm-sub bkm-red">{tb(b.error || "")}</span></>;
    if (b.status === "missing") return <><span className="bkm-pill bkm-pill-bad">{t("File missing")}</span><span className="bkm-sub">{t("The file is no longer in the backup folder")}</span></>;
    if (b.verify_status === "failed") return <><span className="bkm-pill bkm-pill-bad">{t("Damaged")}</span><span className="bkm-sub bkm-red">{tb(b.verify_error || "")}</span></>;
    return (
        <>
            {b.verify_status === "ok"
                ? <span className="bkm-pill bkm-pill-ok">{t("Healthy")}</span>
                : <span className="bkm-pill bkm-pill-muted">{t("Not checked")}</span>}
            {b.test_status === "ok" && <span className="bkm-sub">{t("Restore test: passed")}</span>}
            {b.test_status === "failed" && <span className="bkm-sub bkm-red">{t("Restore test: failed")}</span>}
            {!b.test_status && b.verify_status === "ok" && <span className="bkm-sub">{t("SHA-256 checked")}</span>}
        </>
    );
}

export function DestChips({ b, dests }) {
    if (b.status !== "ready") return "—";
    const failed = (b.destinations || []).filter((d) => d.status === "failed");
    return (
        <>
            <div className="sbk-dests">
                <span className="sbk-dest ok">{t("Server")}</span>
                {(b.destinations || []).map((d) => (
                    <span key={d.id} className={`sbk-dest ${d.status}`}
                          title={d.error ? tb(d.error) : d.path || ""}>{(dests.find((x) => x.id === d.id) || d).name}</span>
                ))}
            </div>
            {failed.map((d) => <span key={d.id} className="bkm-sub bkm-red">{d.name}: {tb(d.error || "")}</span>)}
        </>
    );
}
