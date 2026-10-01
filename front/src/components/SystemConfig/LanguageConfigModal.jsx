import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchSection, saveSection } from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";
import { LANGUAGES, t } from "../../i18n";

const SECTION = "locale";

const LanguageForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors } = useSelector((state) => state.systemConfig);
    const [language, setLanguage] = useState(stored?.config?.default_language || "en");

    const handleSave = async () => {
        const res = await dispatch(saveSection({ section: SECTION, payload: { default_language: language } }));
        if (saveSection.fulfilled.match(res)) onClose();
    };

    return (
        <ConfigModal
            title={t("Language")}
            onClose={onClose}
            onSave={handleSave}
            saveLabel={t("Save")}
            isSaving={!!saving[SECTION]}
            error={errors[SECTION]}
        >
            <label className="sc-field">
                <span>{t("Default language")}</span>
                <select value={language} onChange={(e) => setLanguage(e.target.value)}>
                    {LANGUAGES.map((l) => (
                        <option key={l.code} value={l.code} lang={l.code}>{l.label}</option>
                    ))}
                </select>
            </label>
            <p className="sc-hint">
                {t("For users who have not picked a language themselves. Each user can change it from the menu under their name. Dates follow the language: Solar Hijri in Persian, Gregorian in English.")}
            </p>
        </ConfigModal>
    );
};

export const LanguageConfigModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { sections, loading, errors } = useSelector((state) => state.systemConfig);
    const stored = sections[SECTION];

    useEffect(() => {
        dispatch(fetchSection(SECTION));
    }, [dispatch]);

    if (!stored) {
        return (
            <ConfigModal title={t("Language")} onClose={onClose} onSave={onClose}
                         isLoading={!!loading[SECTION]} error={errors[SECTION]} />
        );
    }
    return <LanguageForm stored={stored} onClose={onClose} />;
};

export default LanguageConfigModal;
