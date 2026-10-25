import { useState } from "react";
import { t } from "../../i18n";
import { formatDate } from "./cveFormat.js";
import { actionText, iso } from "./actionText.js";
import "../../assets/RecommendedAction.css";

/*
 * What to do about a CVE finding (app/modules/cve/recommend.py), the same on the CVE page, in
 * remediation and on the asset: the action, the commands, the advisory, and the notes that change
 * it (Ubuntu Pro, a version from NVD, CISA's required action, an operating system past its end of
 * life).
 */

function Commands({ lines }) {
    const [copied, setCopied] = useState(false);
    const copy = () => {
        navigator.clipboard?.writeText(lines.join("\n")).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        }).catch(() => {});
    };
    return (
        <div className="rca-cmd">
            <pre dir="ltr">{lines.join("\n")}</pre>
            <button type="button" className="rca-copy" onClick={copy}>{copied ? t("Copied") : t("Copy")}</button>
        </div>
    );
}

/** The recommended action of a finding, or one step of an asset's upgrade plan (`closes` findings). */
export function RecommendedAction({ action, closes, title = true }) {
    if (!action) return null;
    const a = action;
    return (
        <section className={`rca ${a.kev_action ? "rca-urgent" : ""}`} aria-label={t("Recommended action")}>
            {title && <h3 className="rca-title">{t("Recommended action")}</h3>}
            <p className="rca-text">{actionText(a)}</p>
            {closes > 1 && <p className="rca-closes">{t("This closes {{closes}} findings on this asset.", { closes })}</p>}

            {a.kev_action && (
                <p className="rca-note rca-note-kev">
                    <b>{t("CISA's required action:")}</b> <span dir="ltr" className="rca-ltr">{a.kev_action}</span>
                    {a.kev_due && <> {t("(due {{date}})", { date: formatDate(a.kev_due) })}</>}
                </p>
            )}
            {a.pro && (
                <p className="rca-note">{t("The fix is published in Ubuntu Pro (ESM) only: attach this machine to Ubuntu Pro, or move to a release where the fix is free.")}</p>
            )}
            {a.eol && (
                <p className="rca-note rca-note-warn">
                    {t("{{title}} is past its end of life and gets no more fixes: move to a supported release.", { title: iso(a.eol.title) })}
                    {a.eol.latest && <> {t("Latest release: {{latest}}.", { latest: iso(a.eol.latest) })}</>}
                </p>
            )}
            {a.check_vendor && (
                <p className="rca-note rca-muted">{t("The version comes from NVD's ranges: check it against the vendor's advisory.")}</p>
            )}

            {a.commands?.length > 0 && <Commands lines={a.commands} />}
            {a.link?.url && (
                <a className="rca-link" href={a.link.url} target="_blank" rel="noreferrer noopener">
                    {a.kind === "package" || a.kind === "reboot" ? t("Advisory") : t("Vendor advisory")}
                    {": "}<span dir="ltr">{a.link.label}</span> ↗
                </a>
            )}
        </section>
    );
}

export default RecommendedAction;
