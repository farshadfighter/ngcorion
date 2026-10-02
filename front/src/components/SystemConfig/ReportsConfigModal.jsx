import React, { useEffect, useState } from "react";

import api from "../../config/api.js";
import { ConfigModal } from "./ConfigModal";
import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";

const MAX_LOGO = 200 * 1024;

/** Letterhead of the reports (organization, logo, classification, footer) and how long they are kept. */
export const ReportsConfigModal = ({ onClose }) => {
    const [form, setForm] = useState(null);
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        api.get("/api/reports/settings/current")
            .then(({ data }) => setForm(data))
            .catch(() => setError(t("Could not load the report settings")));
    }, []);

    const set = (patch) => setForm((f) => ({ ...f, ...patch }));

    const pickLogo = (file) => {
        if (!file) return;
        if (!["image/png", "image/jpeg"].includes(file.type)) { setError(t("The logo must be a PNG or JPEG image")); return; }
        if (file.size > MAX_LOGO) { setError(t("The logo must be smaller than 200 KB")); return; }
        const reader = new FileReader();
        reader.onload = () => { set({ logo: reader.result }); setError(null); };
        reader.readAsDataURL(file);
    };

    const handleSave = () => {
        const days = Number(form.retention_days);
        if (!Number.isInteger(days) || days < 30 || days > 3650) {
            setError(t("Keep reports between 30 and 3650 days"));
            return;
        }
        setSaving(true);
        setError(null);
        api.put("/api/reports/settings/current", { ...form, retention_days: days })
            .then(onClose)
            .catch((e) => setError(typeof e.response?.data?.detail === "string" ? tb(e.response.data.detail)
                : t("Could not save the report settings")))
            .finally(() => setSaving(false));
    };

    return (
        <ConfigModal title={t("Reports")} onClose={onClose} onSave={handleSave} saveLabel={t("Save")}
                     isSaving={saving} isLoading={!form && !error} error={error}>
            {form && (
                <>
                    <label className="sc-field"><span>{t("Organization name")}</span>
                        <input value={form.org_name} maxLength={120} onChange={(e) => set({ org_name: e.target.value })} /></label>
                    <label className="sc-field"><span>{t("Unit (optional)")}</span>
                        <input value={form.org_unit} maxLength={120} placeholder={t("e.g. Information Security")}
                               onChange={(e) => set({ org_unit: e.target.value })} /></label>
                    <div className="sc-field"><span>{t("Logo")}</span>
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                            {form.logo && <img src={form.logo} alt={t("Logo")} style={{ maxHeight: 40, maxWidth: 140 }} />}
                            <label className="bkm-btn bkm-btn-sm" style={{ cursor: "pointer" }}>
                                {form.logo ? t("Change logo") : t("Choose a logo")}
                                <input type="file" accept="image/png,image/jpeg" className="sr-only" onChange={(e) => pickLogo(e.target.files[0])} />
                            </label>
                            <span className="sc-hint" style={{ margin: 0 }}>{t("PNG or JPEG, up to 200 KB")}</span>
                            {form.logo && <button type="button" className="bkm-link" onClick={() => set({ logo: null })}>{t("Remove")}</button>}
                        </div>
                    </div>
                    <label className="sc-field"><span>{t("Default classification")}</span>
                        <select value={form.default_classification} onChange={(e) => set({ default_classification: e.target.value })}>
                            <option value="public">{t("Public")}</option>
                            <option value="internal">{t("Internal")}</option>
                            <option value="confidential">{t("Confidential")}</option>
                        </select></label>
                    <label className="sc-field"><span>{t("Footer text (optional)")}</span>
                        <input value={form.footer_text} maxLength={300} placeholder={t("e.g. For internal use only")}
                               onChange={(e) => set({ footer_text: e.target.value })} /></label>
                    <label className="sc-field"><span>{t("Keep reports for (days)")}</span>
                        <input type="number" min={30} max={3650} value={form.retention_days}
                               onChange={(e) => set({ retention_days: e.target.value })} /></label>
                    <p className="sc-hint">{t("The name and logo appear at the top of every report. Reports older than this are deleted automatically, unless they are pinned.")}</p>
                </>
            )}
        </ConfigModal>
    );
};

export default ReportsConfigModal;
