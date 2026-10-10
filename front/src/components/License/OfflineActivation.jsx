/**
 * Offline (air-gapped) activation and renewal: for an NGCorion that cannot reach the license
 * server. Step 1 downloads a request file (license key, this server's fingerprint, asset count);
 * the license administrator signs a license file for it; step 2 uploads that file. The backend
 * verifies it (signature, this machine, end date) and NGCorion then runs without contact until
 * the file ends - one year.
 *
 * Used on the first-run activation screen (before login) and on the License page (activation, or
 * renewal of an installed offline license: then no key is asked, the installed one is used).
 */
import { useRef, useState } from "react";
import { useDispatch } from "react-redux";
import api from "../../config/api.js";
import { getLicenseStatusThunk } from "../../store/licenseSlice";
import { t } from "../../i18n";

const box = {
    border: "1px solid #E5E7EB", borderRadius: "12px", padding: "18px 20px", backgroundColor: "#ffffff",
    color: "#111827", textAlign: "start",
};
const step = { display: "flex", gap: "12px", alignItems: "flex-start", marginTop: "14px" };
const num = {
    flex: "none", width: "24px", height: "24px", borderRadius: "50%", backgroundColor: "#1e3a5f",
    color: "white", fontSize: "13px", fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center",
};
const btn = (enabled) => ({
    padding: "9px 16px", borderRadius: "8px", border: "none", fontSize: "13.5px", fontWeight: 600,
    backgroundColor: enabled ? "#1e3a5f" : "#D1D5DB", color: "white", cursor: enabled ? "pointer" : "not-allowed",
});

const saveText = (filename, content) => {
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
};

const errorText = (err, fallback) => {
    const detail = err.response?.data?.detail;
    return typeof detail === "string" ? detail : fallback;
};

export const OfflineActivation = ({ renewal = false, initialKey = "" }) => {
    const dispatch = useDispatch();
    const fileRef = useRef(null);
    const [licenseKey, setLicenseKey] = useState(initialKey);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [done, setDone] = useState("");

    const downloadRequest = async () => {
        setBusy(true);
        setError("");
        setDone("");
        try {
            const { data } = await api.post("/api/license/offline/request",
                { license_key: renewal ? null : licenseKey.trim() });
            saveText(data.filename, data.content);
            setDone(t("Request file downloaded. Send it to your license administrator; you will get a license file back."));
        } catch (err) {
            setError(errorText(err, t("The request file could not be made.")));
        } finally {
            setBusy(false);
        }
    };

    const upload = async (ev) => {
        const file = ev.target.files?.[0];
        ev.target.value = "";
        if (!file) return;
        setBusy(true);
        setError("");
        setDone("");
        try {
            await api.post("/api/license/offline/install", { content: await file.text() });
            setDone(t("The license file is installed."));
            dispatch(getLicenseStatusThunk());
        } catch (err) {
            setError(errorText(err, t("The license file could not be installed.")));
        } finally {
            setBusy(false);
        }
    };

    const keyOk = renewal || /^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/.test(licenseKey.trim());

    return (
        <div style={box}>
            <div style={{ fontWeight: 700, fontSize: "15px" }}>
                <i className="fa-solid fa-file-shield" style={{ marginInlineEnd: "8px", color: "#1e3a5f" }} />
                {renewal ? t("Renew the offline license") : t("Offline activation (no internet access)")}
            </div>
            <div style={{ fontSize: "13px", color: "#6B7280", marginTop: "6px", lineHeight: 1.7 }}>
                {renewal
                    ? t("Download a new request file, have your license administrator sign it, and upload the license file you get back.")
                    : t("For a server that cannot reach the license server: exchange two files with your license administrator. The license file is bound to this server and valid for one year.")}
            </div>

            {error && (
                <div style={{ marginTop: "12px", padding: "10px 12px", borderRadius: "8px", backgroundColor: "#FEF2F2",
                              border: "1px solid #FECACA", color: "#B91C1C", fontSize: "13px" }}>{error}</div>
            )}
            {done && !error && (
                <div style={{ marginTop: "12px", padding: "10px 12px", borderRadius: "8px", backgroundColor: "#F0FDF4",
                              border: "1px solid #BBF7D0", color: "#15803D", fontSize: "13px" }}>{done}</div>
            )}

            <div style={step}>
                <span style={num}>1</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13.5px", marginBottom: "8px" }}>{t("Download the request file")}</div>
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                        {!renewal && (
                            <input
                                type="text" dir="ltr" maxLength={19} value={licenseKey}
                                placeholder="XXXX-XXXX-XXXX-XXXX"
                                onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                                style={{ flex: 1, minWidth: "190px", padding: "9px 12px", borderRadius: "8px",
                                         border: "1px solid #D1D5DB", fontFamily: "monospace", letterSpacing: "2px",
                                         textAlign: "center" }}
                            />
                        )}
                        <button onClick={downloadRequest} disabled={busy || !keyOk} style={btn(!busy && keyOk)}>
                            {t("Download request file")}
                        </button>
                    </div>
                </div>
            </div>

            <div style={step}>
                <span style={num}>2</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13.5px", marginBottom: "8px" }}>
                        {t("Upload the license file (.ngclic) your license administrator returned")}
                    </div>
                    <input ref={fileRef} type="file" accept=".ngclic,.txt" onChange={upload} style={{ display: "none" }} />
                    <button onClick={() => fileRef.current?.click()} disabled={busy} style={btn(!busy)}>
                        {busy ? t("Please wait…") : t("Upload license file")}
                    </button>
                </div>
            </div>
        </div>
    );
};
