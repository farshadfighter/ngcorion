import { useState } from "react";
import { useDispatch } from "react-redux";
import { createOwner } from "../../store/requirementSlice";
import { t } from "../../i18n";

export const OwnerModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        full_name: "",
        department: "",
        role: "",
        email: "",
        phone: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.full_name.trim()) {
            newErrors.full_name = t("Full name is required");
        }

        if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            newErrors.email = t("Invalid email format");
        }
        if (formData.phone && !/^\+?[\d\s\-()]{7,15}$/.test(formData.phone)) {
            newErrors.phone = t("Invalid phone number format");
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        // Remove empty strings to avoid validation errors
        const cleanedData = Object.fromEntries(
            Object.entries(formData).filter(([, value]) => value.trim() !== "")
        );

        try {
            await dispatch(createOwner(cleanedData)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create owner:", error);
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
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{t("Add Owner")}</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-grid">

                        {/* Full Name - full width */}
                        <div className="form-group full-width">
                            <label>
                                {t("Full Name")}{" "} <span className="required">*</span>
                            </label>
                            <input
                                type="text"
                                name="full_name"
                                value={formData.full_name}
                                onChange={handleChange}
                                placeholder={t("Enter full name")}
                                className={errors.full_name ? "error" : ""}
                            />
                            {errors.full_name && (
                                <span className="error-message">{errors.full_name}</span>
                            )}
                        </div>

                        {/* Department */}
                        <div className="form-group">
                            <label>{t("Department")}</label>
                            <input
                                type="text"
                                name="department"
                                value={formData.department}
                                onChange={handleChange}
                                placeholder={t("Enter department")}
                            />
                        </div>

                        {/* Role */}
                        <div className="form-group">
                            <label>{t("Role")}</label>
                            <input
                                type="text"
                                name="role"
                                value={formData.role}
                                onChange={handleChange}
                                placeholder={t("Enter role")}
                            />
                        </div>

                        {/* Email */}
                        <div className="form-group">
                            <label>{t("Email")}</label>
                            <input
                                type="email"
                                name="email"
                                value={formData.email}
                                onChange={handleChange}
                                placeholder={t("Enter email")}
                                className={errors.email ? "error" : ""}
                            />
                            {errors.email && (
                                <span className="error-message">{errors.email}</span>
                            )}
                        </div>

                        {/* Phone */}
                        <div className="form-group">
                            <label>{t("Phone")}</label>
                            <input
                                type="text"
                                name="phone"
                                value={formData.phone}
                                onChange={handleChange}
                                placeholder="e.g., +98 912 345 6789"
                                className={errors.phone ? "error" : ""}
                            />
                            {errors.phone && (
                                <span className="error-message">{errors.phone}</span>
                            )}
                        </div>

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