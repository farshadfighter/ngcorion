import React, { useEffect, useMemo, useState } from "react";

import api from "../../config/api.js";
import { ConfigModal } from "./ConfigModal";
import { t } from "../../i18n";

/**
 * Pinned device keys: the SSH host keys and TLS certificates NGCorion pinned on its first
 * connection to each device (GET/DELETE /api/system/device-keys, administrators only).
 *
 * A device that was reinstalled, or got a new certificate, is refused until its old pin is
 * removed here; the next connection then pins whatever the device presents. Removing a pin is
 * also how an impostor would get in, so each removal asks for confirmation and is written to the
 * audit trail with the fingerprint that was dropped.
 */
export const DeviceKeysModal = ({ onClose }) => {
    const [pins, setPins] = useState(null);
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [query, setQuery] = useState("");
    const [confirming, setConfirming] = useState(null);
    const [busy, setBusy] = useState(false);

    const load = () => {
        api.get("/api/system/device-keys")
            .then(({ data }) => setPins(data))
            .catch(() => setError(t("Could not load the pinned device keys")));
    };
    useEffect(load, []);

    const shown = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!pins || !q) return pins || [];
        return pins.filter((p) => [p.host, p.asset_name, p.fingerprint].some((v) => (v || "").toLowerCase().includes(q)));
    }, [pins, query]);

    const keyOf = (p) => `${p.kind}:${p.host}:${p.port}`;

    const forget = (pin) => {
        setBusy(true);
        setError(null);
        api.delete(`/api/system/device-keys/${pin.kind}`, { params: { host: pin.host, port: pin.port } })
            .then(() => {
                setNotice(t("The pinned key of {{host}} was removed. The next connection pins the key the device presents.", { host: `${pin.host}:${pin.port}` }));
                setConfirming(null);
                load();
            })
            .catch((e) => setError(typeof e.response?.data?.detail === "string" ? e.response.data.detail : t("Could not remove the pinned key")))
            .finally(() => setBusy(false));
    };

    return (
        <ConfigModal title={t("Pinned device keys")} onClose={onClose} onSave={onClose}
                     saveLabel={t("Close")} showCancel={false} isLoading={!pins && !error} error={error}>
            <p className="sc-hint">
                {t("NGCorion pins each device's SSH host key (and the HTTPS certificate of API-managed devices) on the first connection and refuses a device that later presents another one. Remove a pin only after the device's owner has confirmed that the device was reinstalled or its key was replaced on purpose.")}
            </p>
            {notice && <p className="sc-test-ok">{notice}</p>}
            {pins && (
                <>
                    <div className="sc-field">
                        <input type="search" value={query} onChange={(e) => setQuery(e.target.value)}
                               placeholder={t("Search address, asset or fingerprint")} aria-label={t("Search address, asset or fingerprint")} />
                    </div>
                    {shown.length === 0 ? (
                        <p className="sc-state">{pins.length === 0 ? t("No device key is pinned yet.") : t("Nothing matches")}</p>
                    ) : (
                        <table className="sc-table">
                            <thead>
                                <tr>
                                    <th>{t("Device")}</th>
                                    <th>{t("Type")}</th>
                                    <th>{t("Fingerprint")}</th>
                                    <th />
                                </tr>
                            </thead>
                            <tbody>
                                {shown.map((p) => (
                                    <React.Fragment key={keyOf(p)}>
                                        <tr>
                                            <td>
                                                <div>{p.asset_name || "—"}</div>
                                                <div dir="ltr" style={{ fontSize: 12, color: "#6b7280" }}>{p.host}:{p.port}</div>
                                            </td>
                                            <td dir="ltr">{p.kind === "ssh" ? `SSH · ${p.key_type}` : t("HTTPS certificate")}</td>
                                            <td dir="ltr" style={{ fontFamily: "monospace", fontSize: 11, wordBreak: "break-all" }}>{p.fingerprint}</td>
                                            <td>
                                                <button type="button" className="sc-btn sc-btn-danger-ghost" disabled={busy} style={{ whiteSpace: "nowrap" }}
                                                        onClick={() => setConfirming(keyOf(p))}>
                                                    {t("Remove pin")}
                                                </button>
                                            </td>
                                        </tr>
                                        {confirming === keyOf(p) && (
                                            <tr>
                                                <td colSpan={4}>
                                                    <p className="sc-warning">
                                                        {t("Remove the pinned key of {{host}}? If the device was not reinstalled, a changed key can mean someone is impersonating it; the next connection would then send them the credentials.", { host: `${p.host}:${p.port}` })}
                                                    </p>
                                                    <div className="sc-row">
                                                        <button type="button" className="sc-btn sc-btn-danger" disabled={busy} onClick={() => forget(p)}>
                                                            {t("Remove pin")}
                                                        </button>
                                                        <button type="button" className="sc-btn sc-btn-ghost" disabled={busy} onClick={() => setConfirming(null)}>
                                                            {t("Cancel")}
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </React.Fragment>
                                ))}
                            </tbody>
                        </table>
                    )}
                    <p className="sc-hint">{t("{{count}} pinned keys", { count: pins.length })}</p>
                </>
            )}
        </ConfigModal>
    );
};

export default DeviceKeysModal;
