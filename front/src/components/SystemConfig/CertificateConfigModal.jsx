import React, { useEffect, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import {
    fetchSection,
    uploadCertificate,
    deleteCertificate,
} from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";
import { t, uiLocale } from "../../i18n";

const SECTION = "certificate";

const formatDate = (value) => {
    if (!value) return "—";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleString(uiLocale());
};

/** Days until expiry, or null when there is no usable date. */
const daysLeft = (value) => {
    if (!value) return null;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return Math.ceil((d.getTime() - Date.now()) / 86400000);
};

/**
 * Unlike the other five sections this one has no JSON payload: it reads
 * metadata straight off the installed file and replaces it through a multipart
 * upload, in one of two shapes the backend accepts — a PEM/DER certificate with
 * an optional key, or a PKCS#12 bundle with its password. Sending both is
 * rejected, so the mode is an explicit choice here.
 */
const CertificateForm = ({ info, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings } = useSelector(
        (state) => state.systemConfig
    );

    const [mode, setMode] = useState("pem"); // "pem" | "pfx"
    const [certFile, setCertFile] = useState(null);
    const [keyFile, setKeyFile] = useState(null);
    const [pfxFile, setPfxFile] = useState(null);
    const [pfxPassword, setPfxPassword] = useState("");
    const [confirmingDelete, setConfirmingDelete] = useState(false);
    const [localError, setLocalError] = useState(null);

    const certInput = useRef(null);
    const keyInput = useRef(null);
    const pfxInput = useRef(null);

    const isBusy = !!saving[SECTION];
    const expiry = daysLeft(info?.expires_at);

    const handleUpload = async () => {
        setLocalError(null);

        const form = new FormData();
        if (mode === "pfx") {
            if (!pfxFile) {
                setLocalError(t("Choose a .pfx bundle to upload."));
                return;
            }
            form.append("pfx_file", pfxFile);
            if (pfxPassword) form.append("pfx_password", pfxPassword);
        } else {
            if (!certFile) {
                setLocalError(t("Choose a certificate file to upload."));
                return;
            }
            form.append("cert_file", certFile);
            if (keyFile) form.append("key_file", keyFile);
        }

        const res = await dispatch(uploadCertificate(form));
        if (uploadCertificate.fulfilled.match(res)) {
            // Clear the pickers so a second upload starts from a clean slate.
            setCertFile(null);
            setKeyFile(null);
            setPfxFile(null);
            setPfxPassword("");
            [certInput, keyInput, pfxInput].forEach((ref) => {
                if (ref.current) ref.current.value = "";
            });
        }
    };

    const handleDelete = async () => {
        setLocalError(null);
        await dispatch(deleteCertificate());
        setConfirmingDelete(false);
    };

    return (
        <ConfigModal
            title={t("Certificate Configurations")}
            onClose={onClose}
            onSave={handleUpload}
            isSaving={isBusy}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
            saveLabel="Upload & install"
        >
            {info?.has_cert ? (
                <div className="sc-cert-info">
                    <p className="sc-cert-row">
                        <span>{t("Issued to")}</span>
                        <strong>{info.issued_to || "—"}</strong>
                    </p>
                    <p className="sc-cert-row">
                        <span>{t("Issued by")}</span>
                        <strong>{info.issued_by || "—"}</strong>
                    </p>
                    <p className="sc-cert-row">
                        <span>{t("Expires")}</span>
                        <strong>
                            {formatDate(info.expires_at)}
                            {expiry !== null && (
                                <em
                                    className={
                                        expiry < 0
                                            ? "sc-cert-expired"
                                            : expiry < 30
                                            ? "sc-cert-soon"
                                            : "sc-cert-ok"
                                    }
                                >
                                    {expiry < 0
                                        ? t(" expired {{value}} days ago", { value: -expiry })
                                        : t(" {{expiry}} days left", { expiry })}
                                </em>
                            )}
                        </strong>
                    </p>
                    <p className="sc-cert-row">
                        <span>{t("Private key")}</span>
                        <strong>{info.has_key ? t("Installed") : t("Not installed")}</strong>
                    </p>
                </div>
            ) : (
                <p className="sc-hint">
                    {t("No certificate is installed. Upload one below to serve the web interface over your own TLS certificate.")}
                </p>
            )}

            <div className="sc-tabs">
                <button
                    type="button"
                    className={`sc-tab${mode === "pem" ? " is-active" : ""}`}
                    onClick={() => setMode("pem")}
                >
                    {t("Certificate + Key")}
                </button>
                <button
                    type="button"
                    className={`sc-tab${mode === "pfx" ? " is-active" : ""}`}
                    onClick={() => setMode("pfx")}
                >
                    {t("PFX Bundle")}
                </button>
            </div>

            {/* Keyed per mode: without it React reuses the same input nodes
                across the two tabs, and the file/password pair flips between
                controlled and uncontrolled. */}
            {mode === "pem" ? (
                <React.Fragment key="pem">
                    <label className="sc-field">
                        <span>{t("Certificate file (.cer / .crt / .pem)")}</span>
                        <input
                            ref={certInput}
                            type="file"
                            accept=".cer,.crt,.pem,.der"
                            onChange={(e) => setCertFile(e.target.files?.[0] || null)}
                        />
                    </label>
                    <label className="sc-field">
                        <span>
                            {t("Private key")}{" "} <em>{t("(optional, PEM)")}</em>
                        </span>
                        <input
                            ref={keyInput}
                            type="file"
                            accept=".key,.pem"
                            onChange={(e) => setKeyFile(e.target.files?.[0] || null)}
                        />
                    </label>
                </React.Fragment>
            ) : (
                <React.Fragment key="pfx">
                    <label className="sc-field">
                        <span>{t("PKCS#12 bundle (.pfx / .p12)")}</span>
                        <input
                            ref={pfxInput}
                            type="file"
                            accept=".pfx,.p12"
                            onChange={(e) => setPfxFile(e.target.files?.[0] || null)}
                        />
                    </label>
                    <label className="sc-field">
                        <span>
                            {t("Bundle password")}{" "} <em>{t("(if protected)")}</em>
                        </span>
                        <input
                            type="password"
                            value={pfxPassword}
                            onChange={(e) => setPfxPassword(e.target.value)}
                            autoComplete="new-password"
                        />
                    </label>
                </React.Fragment>
            )}

            {info?.has_cert && (
                <div className="sc-danger">
                    {confirmingDelete ? (
                        <>
                            <p className="sc-test-note">
                                {t("Remove the installed certificate? Traefik keeps serving its published copy, so HTTPS stays up until you upload a replacement.")}
                            </p>
                            <div className="sc-test-row">
                                <button
                                    type="button"
                                    className="sc-btn sc-btn-ghost"
                                    onClick={() => setConfirmingDelete(false)}
                                    disabled={isBusy}
                                >
                                    {t("Keep it")}
                                </button>
                                <button
                                    type="button"
                                    className="sc-btn sc-btn-danger"
                                    onClick={handleDelete}
                                    disabled={isBusy}
                                >
                                    {t("Remove certificate")}
                                </button>
                            </div>
                        </>
                    ) : (
                        <button
                            type="button"
                            className="sc-btn sc-btn-danger-ghost"
                            onClick={() => setConfirmingDelete(true)}
                            disabled={isBusy}
                        >
                            <i className="fa-solid fa-trash" /> {" "}{t("Remove installed certificate")}
                        </button>
                    )}
                </div>
            )}
        </ConfigModal>
    );
};

/**
 * Certificate Configurations dialog.
 *
 * The form mounts only once the metadata has arrived, matching the other five
 * sections: rendering it during loading would flip its inputs from
 * uncontrolled to controlled when the data lands.
 */
export const CertificateConfigModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { sections, loading, errors } = useSelector(
        (state) => state.systemConfig
    );
    const info = sections[SECTION];

    useEffect(() => {
        dispatch(fetchSection(SECTION));
    }, [dispatch]);

    if (!info) {
        return (
            <ConfigModal
                title={t("Certificate Configurations")}
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <CertificateForm info={info} onClose={onClose} />;
};

export default CertificateConfigModal;
