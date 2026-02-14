import { useState } from "react";
import { useDispatch } from "react-redux";
import { createAssetType } from "../../store/requirementSlice";

export const AssetTypeModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        type_name: "",
        category: "",
        description: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.type_name.trim()) {
            newErrors.type_name = "Type name is required";
        }

        if (!formData.category.trim()) {
            newErrors.category = "Category is required";
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
            <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Add Asset Type</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            Type Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="type_name"
                            value={formData.type_name}
                            onChange={handleChange}
                            placeholder="Enter type name"
                            className={errors.type_name ? "error" : ""}
                        />
                        {errors.type_name && (
                            <span className="error-message">{errors.type_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>
                            Category <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="category"
                            value={formData.category}
                            onChange={handleChange}
                            placeholder="Enter category"
                            className={errors.category ? "error" : ""}
                        />
                        {errors.category && (
                            <span className="error-message">{errors.category}</span>
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