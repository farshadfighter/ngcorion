import React from "react";
import { Link } from "react-router-dom";

import { barWidths, impactDelta, impactRows } from "./hardeningImpact";
import { formatDate, formatDateTime } from "../../../utils/dates";
import { t, n } from "../../../i18n";

/**
 * "Hardening Impact": what hardening changed since the audit the score reads - failed controls and audit
 * risk just after that audit and now, the risk score before the first change and now. Without a change
 * since the audit, says so and opens hardening.
 */
const Row = ({ label, before, now, missing, rose }) => {
    const delta = impactDelta(before, now);
    const [wBefore, wNow] = barWidths(before, now);
    const tone = delta === null ? "" : delta < 0 ? "is-good" : delta > 0 ? "is-bad" : "is-flat";
    return (
        <div className="hri-row">
            <span className="hri-label">{label}</span>
            <div className="hri-values">
                <span className="hri-value is-before">
                    <small>{t("Before")}</small>
                    <b>{before === null ? "—" : n(before)}</b>
                </span>
                <i className="fa-solid fa-arrow-right hri-arrow" aria-hidden="true" />
                <span className="hri-value is-now">
                    <small>{t("Now")}</small>
                    <b>{now === null ? "—" : n(now)}</b>
                </span>
                {delta !== null && <span className={`hri-delta ${tone}`} dir="ltr">{n(delta > 0 ? `+${delta}` : `${delta}`)}</span>}
            </div>
            <div className="hri-bars" aria-hidden="true">
                <span className="hri-bar is-before" style={{ width: `${wBefore}%` }} />
                <span className="hri-bar is-now" style={{ width: `${wNow}%` }} />
            </div>
            {missing && <p className="hri-muted">{missing}</p>}
            {rose && impactDelta(before, now) > 0 && <p className="hri-muted">{rose}</p>}
        </div>
    );
};

export const HardeningImpact = ({ impact }) => {
    const i = impact || {};
    return (
        <section className="ard-card hri">
            <h3 className="ard-card-title">{t("Hardening Impact")}</h3>
            {i.hardened ? (
                <>
                    <p className="hri-sub">
                        {t("Since audit {{id}}: first change {{first}}, last change {{last}}.", {
                            id: i.audit_session_id, first: formatDateTime(i.first_change_at),
                            last: formatDateTime(i.last_change_at),
                        })}
                    </p>
                    <div className="hri-rows">
                        {impactRows(i).map((r) => <Row key={r.key} {...r} />)}
                    </div>
                    <p className="hri-foot">
                        {t("{{changes}} changes run: {{verified}} verified, {{failed}} failed.", {
                            changes: i.changes, verified: i.verified, failed: i.failed,
                        })}
                        {i.awaiting_reaudit > 0 && (
                            <>
                                {" "}{t("{{fixed}} fixed controls still count as failed until the next audit.", { fixed: i.awaiting_reaudit })}
                                {" "}<Link to="/audit/sessions">{t("Run audits")}</Link>
                            </>
                        )}
                    </p>
                </>
            ) : (
                <div className="hri-empty">
                    <p>{t("Nothing has been hardened since the last audit.")}</p>
                    {i.last_hardened_at && (
                        <p className="hri-muted">{t("Last hardened {{when}}, before this audit.", { when: formatDate(i.last_hardened_at) })}</p>
                    )}
                    <Link to="/hardening" className="hri-btn">{t("Harden failed controls")}</Link>
                </div>
            )}
        </section>
    );
};

export default HardeningImpact;
