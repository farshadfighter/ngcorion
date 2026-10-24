/**
 * Dialog adding or editing a network zone.
 */
import { useState } from "react";
import { useDispatch } from "react-redux";
import { createZone } from "../../store/requirementSlice";
import { t } from "../../i18n";
import { PLACES } from "../ArchitectureValidation/architectureFormat.js";

export const NetworkZoneModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        zone_name: "",
        score: "",
        place: "",
        description: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.zone_name.trim()) {
            newErrors.zone_name = t("Zone name is required");
        }
        const score = String(formData.score).trim();
        if (score !== "" && !(Number(score) >= 0 && Number(score) <= 100)) {
            newErrors.score = t("Enter a score from 0 to 100");
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            const score = String(formData.score).trim();
            await dispatch(createZone({ ...formData, score: score === "" ? null : Number(score) })).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create zone:", error);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (errors[name]) {
            setErrors((prev) => ({ ...prev, [name]: "" }));
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{t("Add Network Zone")}</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                           {t("Zone Name")}{" "} <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="zone_name"
                            value={formData.zone_name}
                            onChange={handleChange}
                            placeholder={t("Enter zone name")}
                            className={errors.zone_name ? "error" : ""}
                        />
                        {errors.zone_name && (
                            <span className="error-message">{errors.zone_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>{t("Exposure score (0-100)")}</label>
                        <input
                            type="number"
                            name="score"
                            min="0"
                            max="100"
                            value={formData.score}
                            onChange={handleChange}
                            className={errors.score ? "error" : ""}
                        />
                        <span className="field-hint">
                            {t("How exposed an asset in this zone is; its risk score uses it. Left empty, it is the score of an asset with no zone.")}
                        </span>
                        {errors.score && (
                            <span className="error-message">{errors.score}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>{t("Place in the network (Cisco SAFE)")}</label>
                        <select name="place" value={formData.place} onChange={handleChange}>
                            <option value="">{t("From the zone's name")}</option>
                            {PLACES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                        </select>
                        <span className="field-hint">{t("Architecture Validation checks the firewalls between places by it.")}</span>
                    </div>

                    <div className="form-group">
                        <label>{t("Description")}</label>
                        <textarea
                            name="description"
                            value={formData.description}
                            onChange={handleChange}
                            placeholder={t("Enter description")}
                            rows="3"
                        />
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                           {t("Cancel")}
                        </button>
                        <button type="submit" className="btn-submit">
                           {t("Create")}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};