import { useState } from "react";
import api from "../../config/api.js";
import { Icon } from "./CveIcons.jsx";
import { t } from "../../i18n";
import { tx } from "../../i18n/tx";

const isoDay = (d) => d.toISOString().slice(0, 10);

/** Choose what goes in a package for an air-gapped NGCorion, then start the export. */
export function CveExportModal({ onStarted, onClose }) {
    const [kind, setKind] = useState("delta");
    const [today] = useState(() => new Date());
    const [since, setSince] = useState(() => isoDay(new Date(today.getTime() - 30 * 86400000)));
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    const start = async () => {
        setBusy(true);
        setError(null);
        try {
            const body = kind === "full" ? { kind } : { kind, since: `${since}T00:00:00` };
            const { data } = await api.post("/api/cve/db/export", body);
            onStarted(data);
        } catch (err) {
            setError(err.response?.data?.detail || t("The export could not be started"));
            setBusy(false);
        }
    };

    return (
        <div className="cvx-overlay" role="dialog" aria-modal="true" aria-labelledby="cvx-export-title">
            <section className="cvx-modal">
                <header className="cvx-modal-head">
                    <h2 id="cvx-export-title">{t("Create update package")}</h2>
                    <p>{t("For an NGCorion without internet access. The package is signed with this server's key.")}</p>
                </header>
                <div className="cvx-modal-body">
                    <fieldset className="cvx-choice">
                        <legend className="cvx-sr">{t("Package contents")}</legend>
                        <label className={`cvx-option ${kind === "delta" ? "is-on" : ""}`}>
                            <input type="radio" name="kind" value="delta" checked={kind === "delta"} onChange={() => setKind("delta")} />
                            <div>
                                <b>{t("Changes since a date")}</b>
                                <span>{t("Small. Pick the date the other server was last updated, or earlier.")}</span>
                                {kind === "delta" && (
                                    <input type="date" className="cvx-input cvx-date" value={since} max={isoDay(today)}
                                           aria-label={t("Changes since")} onChange={(e) => setSince(e.target.value)} />
                                )}
                            </div>
                        </label>
                        <label className={`cvx-option ${kind === "full" ? "is-on" : ""}`}>
                            <input type="radio" name="kind" value="full" checked={kind === "full"} onChange={() => setKind("full")} />
                            <div>
                                <b>{t("The whole database")}</b>
                                <span>{t("Large (hundreds of MB). For a first load, or when the other server is far behind.")}</span>
                            </div>
                        </label>
                    </fieldset>
                    <div className="cvx-note">
                        {tx("The receiving server accepts the package once this server's public key is added under {{trusted}} there.", { trusted: <b>{t("Trusted keys")}</b> })}
                    </div>
                    {error && <div className="cvx-note cvx-note-error">{error}</div>}
                </div>
                <footer className="cvx-modal-foot">
                    <button type="button" className="cvx-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="cvx-btn cvx-btn-primary" onClick={start}
                            disabled={busy || (kind === "delta" && !since)}>
                        <Icon name="package" size={16} /> {busy ? t("Starting…") : t("Create package")}
                    </button>
                </footer>
            </section>
        </div>
    );
}
