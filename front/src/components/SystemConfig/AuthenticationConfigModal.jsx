import React, { useEffect, useState } from "react";

import api from "../../config/api.js";
import { ConfigModal } from "./ConfigModal";
import { n, t } from "../../i18n";
import { tb, tv } from "../../i18n/backendText";
import "../../assets/TwoStep.css";

const ROLES = ["admin", "manager", "user", "guest"];

/**
 * Two-step sign-in policy (GET/PUT /api/system/authentication, system administrators): the roles
 * that must use it and the days such a user has to set it up from their next sign-in. System
 * administrators always get none. Below it, how many users of each role have it on.
 */
export const AuthenticationConfigModal = ({ onClose }) => {
    const [form, setForm] = useState(null);
    const [users, setUsers] = useState([]);
    const [roles, setRoles] = useState({});
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        Promise.all([api.get("/api/system/authentication"), api.get("/api/system/authentication/users"),
                     api.get("/api/users/")])
            .then(([p, s, u]) => {
                setForm(p.data);
                setUsers(s.data);
                setRoles(Object.fromEntries(u.data.map((x) => [x.id, x.role])));
            })
            .catch(() => setError(t("Could not load the two-step sign-in settings")));
    }, []);

    const toggle = (role) => setForm((f) => ({
        ...f,
        required_roles: f.required_roles.includes(role) ? f.required_roles.filter((r) => r !== role) : [...f.required_roles, role],
    }));

    const handleSave = () => {
        const grace = Number(form.grace_days);
        if (!Number.isInteger(grace) || grace < 0 || grace > 90) {
            setError(t("The grace period must be a whole number of days from 0 to 90."));
            return;
        }
        setSaving(true);
        setError(null);
        api.put("/api/system/authentication", { required_roles: form.required_roles, grace_days: grace })
            .then(onClose)
            .catch((e) => setError(typeof e.response?.data?.detail === "string" ? tb(e.response.data.detail)
                : t("Could not save the two-step sign-in settings")))
            .finally(() => setSaving(false));
    };

    const count = (role) => {
        const mine = users.filter((u) => roles[u.user_id] === role);
        return { all: mine.length, on: mine.filter((u) => u.enabled).length };
    };

    return (
        <ConfigModal title={t("Two-step sign-in")} onClose={onClose} onSave={handleSave}
                     saveLabel={t("Save")} isSaving={saving} isLoading={!form && !error} error={error}>
            {form && (
                <>
                    <p className="sc-hint">{t("After the password, a 6-digit code from an authenticator app on the user's phone (TOTP). Works offline; no SMS or email needed.")}</p>
                    <table className="sc-table">
                        <thead>
                            <tr><th>{t("Role")}</th><th>{t("Required")}</th><th>{t("Users with it on")}</th></tr>
                        </thead>
                        <tbody>
                            {ROLES.map((role) => {
                                const c = count(role);
                                return (
                                    <tr key={role}>
                                        <td>{tv(role)}</td>
                                        <td>
                                            <label className="ts-check">
                                                <input type="checkbox" checked={form.required_roles.includes(role)} onChange={() => toggle(role)} />
                                                {form.required_roles.includes(role) ? t("Required") : t("Optional")}
                                            </label>
                                        </td>
                                        <td>{t("{{on}} of {{all}}", { on: c.on, all: c.all })}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                    <label className="sc-field"><span>{t("Days to set it up (grace period)")}</span>
                        <input type="number" min={0} max={90} value={form.grace_days}
                               onChange={(e) => setForm((f) => ({ ...f, grace_days: e.target.value }))} /></label>
                    <p className="sc-hint">
                        {t("Counted from each user's next sign-in. When it ends, the user can only set it up before using anything else. System administrators have no grace period. A user who lost the phone and the recovery codes is reset from User Management; the last administrator, from the VM console's password reset.")}
                    </p>
                    {form.required_roles.length === 0 && (
                        <p className="sc-hint ts-warn">{t("No role requires it: a stolen password alone opens any account that has not turned it on.")}</p>
                    )}
                    <p className="sc-hint">{t("Users with it on: {{on}} of {{all}}", { on: n(users.filter((u) => u.enabled).length), all: n(users.length) })}</p>
                </>
            )}
        </ConfigModal>
    );
};

export default AuthenticationConfigModal;
