import { useCallback, useEffect, useState } from "react";

import api from "../../config/api.js";
import { apiErrorText } from "../../utils/apiError.js";
import { t } from "../../i18n";

const hint = { display: "block", color: "#6c757d", fontSize: "11px", marginTop: "3px" };

/**
 * Other addresses of an asset (GET/POST/DELETE /api/assets/{id}/addresses): addresses it also sends from,
 * such as a FortiGate's logging interface or the units of an HA cluster - syslog from them is the asset's.
 * Saved at once, apart from the form around it.
 */
export function OtherAddresses({ assetId, disabled }) {
    const [rows, setRows] = useState([]);
    const [address, setAddress] = useState("");
    const [note, setNote] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);

    const load = useCallback(() => api.get(`/api/assets/${assetId}/addresses`)
        .then(({ data }) => setRows(Array.isArray(data) ? data : []))
        .catch((e) => setError(apiErrorText(e, t("Could not load the addresses")))), [assetId]);
    useEffect(() => { load(); }, [load]);

    const add = () => {
        setBusy(true);
        setError(null);
        api.post(`/api/assets/${assetId}/addresses`, { address: address.trim(), note: note.trim() || null })
            .then(() => { setAddress(""); setNote(""); return load(); })
            .catch((e) => setError(apiErrorText(e, t("Could not add the address"))))
            .finally(() => setBusy(false));
    };
    const remove = (id) => {
        setBusy(true);
        setError(null);
        api.delete(`/api/assets/${assetId}/addresses/${id}`)
            .then(load)
            .catch((e) => setError(apiErrorText(e, t("Could not remove the address"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="form-group full-width other-addresses">
            <label>{t("Other addresses")}</label>
            <span style={hint}>{t("Addresses this asset also sends from - a logging interface, the units of an HA cluster. Syslog from them is the asset's.")}</span>
            {rows.length > 0 && (
                <ul className="other-addresses-list">
                    {rows.map((r) => (
                        <li key={r.id}>
                            <span dir="ltr" className="other-addresses-ip">{r.address}</span>
                            {r.note && <span className="other-addresses-note">{r.note}</span>}
                            <button type="button" className="btn-icon" title={t("Remove")} aria-label={t("Remove {{address}}", { address: r.address })}
                                    disabled={busy || disabled} onClick={() => remove(r.id)}>
                                <i className="fa-solid fa-xmark" aria-hidden="true" />
                            </button>
                        </li>
                    ))}
                </ul>
            )}
            <div className="other-addresses-add">
                <input type="text" dir="ltr" value={address} placeholder="10.0.0.2" maxLength={45} disabled={busy || disabled}
                       aria-label={t("Address")} onChange={(e) => setAddress(e.target.value)} />
                <input type="text" value={note} placeholder={t("What it is (optional)")} maxLength={120} disabled={busy || disabled}
                       aria-label={t("Note")} onChange={(e) => setNote(e.target.value)} />
                <button type="button" className="btn-secondary" disabled={busy || disabled || !address.trim()} onClick={add}>{t("Add")}</button>
            </div>
            {error && <span style={{ ...hint, color: "#dc3545" }}>{error}</span>}
        </div>
    );
}

export default OtherAddresses;
