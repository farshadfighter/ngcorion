/**
 * Dialog adding or editing an asset type (name, category, physical or virtual, icon).
 */
import { useState } from "react";
import { useDispatch } from "react-redux";
import { createAssetType } from "../../store/requirementSlice";
import IconPicker from "../shared/IconPicker.jsx";
import { suggestIconFromName } from "../shared/assetIcons.js";
import { t } from "../../i18n";

export const AssetTypeModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        type_name: "",
        category: "",
        description: "",
        icon: "", // automatic until one is picked
        is_virtual: false,
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.type_name.trim()) {
            newErrors.type_name = t("Type name is required");
        }

        if (!formData.category.trim()) {
            newErrors.category = t("Category is required");
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            await dispatch(createAssetType(formData)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create asset type:", error);
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
            <div className="modal-content modal-small" style={{ maxWidth: 680, width: "100%" }} onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{t("Add Asset Type")}</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            {t("Type Name")}{" "} <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="type_name"
                            value={formData.type_name}
                            onChange={handleChange}
                            placeholder={t("Enter type name")}
                            className={errors.type_name ? "error" : ""}
                        />
                        {errors.type_name && (
                            <span className="error-message">{errors.type_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>
                            {t("Category")}{" "} <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="category"
                            value={formData.category}
                            onChange={handleChange}
                            placeholder={t("Enter category")}
                            className={errors.category ? "error" : ""}
                        />
                        {errors.category && (
                            <span className="error-message">{errors.category}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>{t("Runs as")}</label>
                        <select
                            name="is_virtual"
                            value={formData.is_virtual ? "virtual" : "physical"}
                            onChange={(e) => setFormData((prev) => ({ ...prev, is_virtual: e.target.value === "virtual" }))}
                        >
                            <option value="physical">{t("Physical")}</option>
                            <option value="virtual">{t("Virtual (runs on a physical server)")}</option>
                        </select>
                        <span className="field-hint">{t("Each asset of a virtual type names the physical server it runs on.")}</span>
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

                    <div className="form-group">
                        <IconPicker
                            value={formData.icon}
                            onChange={(icon) => setFormData((prev) => ({ ...prev, icon }))}
                            automatic={suggestIconFromName(formData.type_name)}
                            autoHint={t("from the name")}
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