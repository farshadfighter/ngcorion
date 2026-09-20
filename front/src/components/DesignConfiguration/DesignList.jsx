import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import {
    fetchDesigns,
    createDesign,
    fetchDesignTemplates,
    fetchTemplateScales,
    clearMessages,
} from "../../store/designSlice.jsx";
import "../../assets/DesignConfiguration.css";

export const DesignList = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { designs, templates, templateScales, isLoading, error, successMessage } = useSelector(
        (state) => state.design
    );
    const [showCreate, setShowCreate] = useState(false);
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [templateId, setTemplateId] = useState(null); // null = blank canvas
    const [templateScale, setTemplateScale] = useState("medium");

    useEffect(() => {
        dispatch(fetchDesigns());
        dispatch(fetchDesignTemplates());
        dispatch(fetchTemplateScales());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleCreate = () => {
        if (!name.trim()) return;
        dispatch(
            createDesign({
                name: name.trim(),
                description: description.trim() || undefined,
                template_id: templateId || undefined,
                template_scale: templateId ? templateScale : undefined,
            })
        ).then((action) => {
            if (action.payload?.id) {
                setShowCreate(false);
                setName("");
                setDescription("");
                setTemplateId(null);
                setTemplateScale("medium");
                navigate(`/design-configuration/designs/${action.payload.id}`);
            }
        });
    };

    return (
        <div className="dc-container">
            <div className="dc-toolbar">
                <div className="dc-toolbar-info">{designs.length} design(s)</div>
                <button className="dc-btn dc-btn-primary" onClick={() => setShowCreate(true)}>
                    <i className="fa-solid fa-plus" /> New Design
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-table-container">
                {isLoading ? (
                    <div className="dc-empty">Loading designs…</div>
                ) : designs.length === 0 ? (
                    <div className="dc-empty">No designs yet. Click "New Design" to start one.</div>
                ) : (
                    <table className="dc-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Description</th>
                                <th>Status</th>
                                <th>Latest version</th>
                                <th>Updated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {designs.map((d) => (
                                <tr key={d.id} onClick={() => navigate(`/design-configuration/designs/${d.id}`)}>
                                    <td className="dc-cell-strong">{d.name}</td>
                                    <td>{d.description || "—"}</td>
                                    <td>
                                        <span className={`dc-status dc-status-${d.status}`}>{d.status}</span>
                                    </td>
                                    <td>v{d.latest_version_number ?? 1}</td>
                                    <td>{d.updated_at ? new Date(d.updated_at).toLocaleString() : "—"}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {showCreate && (
                <div className="dc-modal-backdrop" onClick={() => setShowCreate(false)}>
                    <div className="dc-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>New design</h3>
                        <div className="dc-field">
                            <label>Name</label>
                            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Branch Office Refresh" />
                        </div>
                        <div className="dc-field">
                            <label>Description</label>
                            <textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
                        </div>

                        <div className="dc-field">
                            <label>Start from</label>
                            <div className="dc-template-options">
                                <button
                                    type="button"
                                    className={`dc-template-card${templateId === null ? " dc-template-card-selected" : ""}`}
                                    onClick={() => setTemplateId(null)}
                                >
                                    <span className="dc-template-card-title">Blank canvas</span>
                                    <span className="dc-template-card-desc">Start with an empty design and add components yourself.</span>
                                </button>
                                {templates.map((t) => (
                                    <button
                                        type="button"
                                        key={t.id}
                                        className={`dc-template-card${templateId === t.id ? " dc-template-card-selected" : ""}`}
                                        onClick={() => setTemplateId(t.id)}
                                    >
                                        <span className="dc-template-card-framework">{t.framework}</span>
                                        <span className="dc-template-card-title">{t.name}</span>
                                        <span className="dc-template-card-desc">{t.description}</span>
                                    </button>
                                ))}
                            </div>
                        </div>

                        {templateId && (
                            <div className="dc-field">
                                <label>Network size</label>
                                <select value={templateScale} onChange={(e) => setTemplateScale(e.target.value)}>
                                    {templateScales.map((s) => (
                                        <option key={s.id} value={s.id}>{s.label}</option>
                                    ))}
                                </select>
                            </div>
                        )}

                        <div className="dc-modal-actions">
                            <button className="dc-btn" onClick={() => setShowCreate(false)}>Cancel</button>
                            <button className="dc-btn dc-btn-primary" onClick={handleCreate} disabled={!name.trim()}>
                                Create
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DesignList;
