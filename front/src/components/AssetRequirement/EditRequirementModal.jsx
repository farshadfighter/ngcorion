import React, { useState } from "react";
import { useDispatch } from "react-redux";

import {
    updateAssetType,
    updateOwner,
    updateLocation,
    updateZone,
    updateOS,
    updateVendor,
} from "../../store/requirementSlice";

/**
 * One edit dialog for all six requirement tabs.
 *
 * The tabs only differ by which fields they carry, so the shape lives in this
 * table rather than in six near-identical modals. `required` is validated
 * before dispatch; everything else is optional.
 */
const REQUIREMENT_FORMS = {
    assetType: {
        title: "Asset Type",
        thunk: updateAssetType,
        fields: [
            { name: "type_name", label: "Type Name", required: true },
            { name: "category", label: "Category" },
            { name: "description", label: "Description", type: "textarea" },
        ],
    },
    owner: {
        title: "Owner",
        thunk: updateOwner,
        fields: [
            { name: "full_name", label: "Full Name", required: true },
            { name: "department", label: "Department" },
            { name: "role", label: "Role" },
            { name: "email", label: "Email", type: "email" },
            { name: "phone", label: "Phone" },
        ],
    },
    location: {
        title: "Location",
        thunk: updateLocation,
        fields: [
            { name: "site_name", label: "Site Name", required: true },
            { name: "rack_name", label: "Rack Name" },
            { name: "room", label: "Room" },
            { name: "floor", label: "Floor" },
            { name: "unit", label: "Unit" },
        ],
    },
    zone: {
        title: "Network Zone",
        thunk: updateZone,
        fields: [
            { name: "zone_name", label: "Zone Name", required: true },
            { name: "description", label: "Description", type: "textarea" },
        ],
    },
    os: {
        title: "OS Entry",
        thunk: updateOS,
        fields: [
            { name: "os_name", label: "OS Name", required: true },
            { name: "os_version", label: "Version" },
        ],
    },
    vendor: {
        title: "Vendor",
        thunk: updateVendor,
        fields: [
            { name: "vendor_name", label: "Vendor Name", required: true },
            { name: "vendor_type", label: "Vendor Type" },
        ],
    },
};

export const EditRequirementModal = ({ kind, item, onClose }) => {
    const dispatch = useDispatch();
    const config = REQUIREMENT_FORMS[kind];

    const [form, setForm] = useState(() =>
        Object.fromEntries(
            config.fields.map((f) => [f.name, item?.[f.name] ?? ""])
        )
    );
    const [errors, setErrors] = useState({});
    const [isSaving, setIsSaving] = useState(false);

    const setField = (name, value) => {
        setForm((prev) => ({ ...prev, [name]: value }));
        setErrors((prev) => (prev[name] ? { ...prev, [name]: null } : prev));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        const found = {};
        config.fields.forEach((f) => {
            if (f.required && !String(form[f.name] ?? "").trim()) {
                found[f.name] = `${f.label} is required`;
            }
        });
        setErrors(found);
        if (Object.keys(found).length > 0) return;

        setIsSaving(true);
        const result = await dispatch(
            config.thunk({ id: item.id, data: form })
        );
        setIsSaving(false);

        // A rejected update leaves the dialog open so the entered values are
        // not lost; the tab's error banner explains why it failed.
        if (config.thunk.fulfilled.match(result)) onClose();
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div
                className="modal-content modal-small"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3>Edit {config.title}</h3>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {config.fields.map((f) => (
                            <div className="form-group" key={f.name}>
                                <label>
                                    {f.label}
                                    {f.required && <span className="required"> *</span>}
                                </label>
                                {f.type === "textarea" ? (
                                    <textarea
                                        rows={3}
                                        value={form[f.name]}
                                        onChange={(e) => setField(f.name, e.target.value)}
                                    />
                                ) : (
                                    <input
                                        type={f.type || "text"}
                                        value={form[f.name]}
                                        onChange={(e) => setField(f.name, e.target.value)}
                                    />
                                )}
                                {errors[f.name] && (
                                    <span className="error-text">{errors[f.name]}</span>
                                )}
                            </div>
                        ))}
                    </div>

                    <div className="modal-actions">
                        <button
                            type="button"
                            className="btn-cancel"
                            onClick={onClose}
                            disabled={isSaving}
                        >
                            Cancel
                        </button>
                        <button type="submit" className="btn-submit" disabled={isSaving}>
                            {isSaving ? "Saving…" : "Save changes"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default EditRequirementModal;
