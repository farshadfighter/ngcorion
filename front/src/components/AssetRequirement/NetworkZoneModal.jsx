import { useState } from "react";
import { useDispatch } from "react-redux";
import { createZone } from "../../store/requirementSlice";

export const NetworkZoneModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        zone_name: "",
        description: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.zone_name.trim()) {
            newErrors.zone_name = "Zone name is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            await dispatch(createZone(formData)).unwrap();
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
                    <h2>Add Network Zone</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            Zone Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="zone_name"
                            value={formData.zone_name}
                            onChange={handleChange}
                            placeholder="Enter zone name"
                            className={errors.zone_name ? "error" : ""}
                        />
                        {errors.zone_name && (
                            <span className="error-message">{errors.zone_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>Description</label>
                        <textarea
                            name="description"
                            value={formData.description}
                            onChange={handleChange}
                            placeholder="Enter description"
                            rows="3"
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