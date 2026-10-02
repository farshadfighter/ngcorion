import React, { useEffect, useState } from "react";

import api from "../../config/api.js";
import { ConfigModal } from "./ConfigModal";
import { t } from "../../i18n";

const BANDS = [
    ["kev", t("Exploited in the wild (KEV)")],
    ["critical", t("Critical")],
    ["high", t("High")],
    ["medium", t("Medium")],
    ["low", t("Low")],
];

/** Days to fix a finding, and the longest a risk acceptance may last, per severity. */
export const RemediationConfigModal = ({ onClose }) => {
    const [form, setForm] = useState(null);
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        api.get("/api/remediation/settings")
            .then(({ data }) => setForm(data))
            .catch(() => setError(t("Could not load the remediation settings")));
    }, []);

    const set = (group, key, value) => setForm((f) => ({ ...f, [group]: { ...f[group], [key]: value } }));

    const handleSave = () => {
        const clean = (g) => Object.fromEntries(BANDS.map(([k]) => [k, Number(form[g][k])]));
        const payload = { sla: clean("sla"), accept_max: clean("accept_max") };
        if (Object.values(payload.sla).concat(Object.values(payload.accept_max)).some((v) => !Number.isInteger(v) || v < 1)) {
            setError(t("Every value must be a whole number of days, at least 1."));
            return;
        }
        setSaving(true);
        setError(null);
        api.put("/api/remediation/settings", payload)
            .then(onClose)
            .catch((e) => setError(e.response?.data?.detail && typeof e.response.data.detail === "string"
                ? e.response.data.detail : t("Could not save the remediation settings")))
            .finally(() => setSaving(false));
    };

    return (
        <ConfigModal title={t("Remediation deadlines")} onClose={onClose} onSave={handleSave}
                     saveLabel={t("Save")} isSaving={saving} isLoading={!form && !error} error={error}>
            {form && (
                <>
                    <table className="sc-table">
                        <thead>
                            <tr><th>{t("Severity")}</th><th>{t("Days to fix")}</th><th>{t("Longest risk acceptance (days)")}</th></tr>
                        </thead>
                        <tbody>
                            {BANDS.map(([key, label]) => (
                                <tr key={key}>
                                    <td>{label}</td>
                                    <td><input type="number" min={1} max={3650} value={form.sla[key]} aria-label={`${label} · ${t("Days to fix")}`}
                                               onChange={(e) => set("sla", key, e.target.value)} /></td>
                                    <td><input type="number" min={1} max={3650} value={form.accept_max[key]} aria-label={`${label} · ${t("Longest risk acceptance (days)")}`}
                                               onChange={(e) => set("accept_max", key, e.target.value)} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    <p className="sc-hint">
                        {t("A finding's deadline counts from the day it is first seen and can be changed on the finding itself. New values apply to findings recorded from now on.")}
                    </p>
                </>
            )}
        </ConfigModal>
    );
};

export default RemediationConfigModal;
