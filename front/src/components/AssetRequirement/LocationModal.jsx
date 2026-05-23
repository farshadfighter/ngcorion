import { useState } from "react";
import { useDispatch } from "react-redux";
import { createLocation } from "../../store/requirementSlice";

export const LocationModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        site_name: "",
        rack_name: "",
        room: "",
        floor: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.site_name.trim()) {
            newErrors.site_name = "Site name is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            const payload = {
                site_name: formData.site_name,
                rack_name: formData.rack_name || null,
                room: formData.room || null,
                floor: formData.floor || null,
            };

            console.log("Sending payload:", JSON.stringify(payload, null, 2));
            await dispatch(createLocation(payload)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create location:", error);
            console.error("Full error object:", JSON.stringify(error, null, 2));
            if (error.response) {
                console.error("Response status:", error.response.status);
                console.error("Response data:", JSON.stringify(error.response.data, null, 2));
            }
            if (Array.isArray(error)) {
                console.error("Error array details:", JSON.stringify(error, null, 2));
            }
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
                    <h2>Add Location</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            Site Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="site_name"
                            value={formData.site_name}
                            onChange={handleChange}
                            placeholder="Enter site name"
                            className={errors.site_name ? "error" : ""}
                        />
                        {errors.site_name && (
                            <span className="error-message">{errors.site_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>Rack Name</label>
                        <input
                            type="text"
                            name="rack_name"
                            value={formData.rack_name}
                            onChange={handleChange}
                            placeholder="Enter rack name"
                        />
                    </div>

                    <div className="form-group">
                        <label>Room</label>
                        <input
                            type="text"
                            name="room"
                            value={formData.room}
                            onChange={handleChange}
                            placeholder="Enter room"
                        />
                    </div>

                    <div className="form-group">
                        <label>Floor</label>
                        <input
                            type="text"
                            name="floor"
                            value={formData.floor}
                            onChange={handleChange}
                            placeholder="Enter floor"
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