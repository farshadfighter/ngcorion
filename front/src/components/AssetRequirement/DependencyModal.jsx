import { useState } from "react";
import { useDispatch } from "react-redux";
import { createDependency } from "../../store/requirementSlice";

export const DependencyModal = ({ onClose, relationTypes }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        asset_id: "",
        depends_on_id: "",
        relation_type: "",
        description: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.asset_id) {
            newErrors.asset_id = "Asset ID is required";
        }

        if (!formData.depends_on_id) {
            newErrors.depends_on_id = "Depends On ID is required";
        }

        if (!formData.relation_type) {
            newErrors.relation_type = "Relation type is required";
        }

        if (formData.asset_id === formData.depends_on_id) {
            newErrors.depends_on_id = "Asset cannot depend on itself";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            const payload = {
                asset_id: parseInt(formData.asset_id),
                depends_on_id: parseInt(formData.depends_on_id),
                relation_type: formData.relation_type,
                description: formData.description || null,
            };

            await dispatch(createDependency(payload)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create dependency:", error);
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
                    <h2>Add Dependency</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            Asset ID <span className="required">*</span>
                        </label>
                        <input
                            type="number"
                            name="asset_id"
                            value={formData.asset_id}
                            onChange={handleChange}
                            placeholder="Enter asset ID"
                            className={errors.asset_id ? "error" : ""}
                        />
                        {errors.asset_id && (
                            <span className="error-message">{errors.asset_id}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>
                            Depends On ID <span className="required">*</span>
                        </label>
                        <input
                            type="number"
                            name="depends_on_id"
                            value={formData.depends_on_id}
                            onChange={handleChange}
                            placeholder="Enter dependency asset ID"
                            className={errors.depends_on_id ? "error" : ""}
                        />
                        {errors.depends_on_id && (
                            <span className="error-message">{errors.depends_on_id}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>
                            Relation Type <span className="required">*</span>
                        </label>
                        <select
                            name="relation_type"
                            value={formData.relation_type}
                            onChange={handleChange}
                            className={errors.relation_type ? "error" : ""}
                        >
                            <option value="">Select relation type</option>
                            {relationTypes.map((type) => (
                                <option key={type} value={type}>
                                    {type}
                                </option>
                            ))}
                        </select>
                        {errors.relation_type && (
                            <span className="error-message">{errors.relation_type}</span>
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