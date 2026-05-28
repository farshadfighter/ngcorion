import { useState } from "react";
import { useDispatch } from "react-redux";
import { createOS } from "../../store/requirementSlice";

export const OSCatalogModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        os_name: "",
        os_version: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.os_name.trim()) {
            newErrors.os_name = "OS name is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            const payload = { ...formData };
            if (!payload.os_version.trim()) delete payload.os_version;
            await dispatch(createOS(payload)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create OS:", error);
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
                    <h2>Add OS</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            OS Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="os_name"
                            value={formData.os_name}
                            onChange={handleChange}
                            placeholder="e.g., Ubuntu, Windows Server, FortiOS"
                            className={errors.os_name ? "error" : ""}
                        />
                        {errors.os_name && (
                            <span className="error-message">{errors.os_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>OS Version</label>
                        <input
                            type="text"
                            name="os_version"
                            value={formData.os_version}
                            onChange={handleChange}
                            placeholder="e.g., 22.04, 2022, 7.2"
                        />
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="submit" className="btn-submit">
                            Create
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};