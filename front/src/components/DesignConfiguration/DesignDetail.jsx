import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useParams } from "react-router-dom";
import { fetchDesignDetail, createDesignVersion, clearMessages } from "../../store/designSlice.jsx";
import "../../assets/DesignConfiguration.css";

export const DesignDetail = () => {
    const { designId } = useParams();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { currentDesign, isLoading, error, successMessage } = useSelector((state) => state.design);
    const [showNewVersion, setShowNewVersion] = useState(false);
    const [notes, setNotes] = useState("");
    const [cloneFrom, setCloneFrom] = useState("");

    useEffect(() => {
        dispatch(fetchDesignDetail(designId));
    }, [dispatch, designId]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleCreateVersion = () => {
        dispatch(
            createDesignVersion({
                designId: Number(designId),
                notes: notes.trim() || undefined,
                cloneFromVersionId: cloneFrom ? Number(cloneFrom) : undefined,
            })
        ).then((action) => {
            if (action.payload?.id) {
                setShowNewVersion(false);
                setNotes("");
                setCloneFrom("");
                navigate(`/design-configuration/versions/${action.payload.id}`);
            }
        });
    };

    if (isLoading || !currentDesign) {
        return <div className="dc-container"><div className="dc-empty">Loading…</div></div>;
    }

    const { design, versions } = currentDesign;

    return (
        <div className="dc-container">
            <div className="dc-toolbar">
                <div>
                    <h2 className="dc-page-title">{design.name}</h2>
                    {design.description && <p className="dc-page-subtitle">{design.description}</p>}
                </div>
                <button className="dc-btn dc-btn-primary" onClick={() => setShowNewVersion(true)}>
                    <i className="fa-solid fa-code-branch" /> New Version
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-table-container">
                <table className="dc-table">
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Notes</th>
                            <th>Created</th>
                        </tr>
                    </thead>
                    <tbody>
                        {[...versions].reverse().map((v) => (
                            <tr key={v.id} onClick={() => navigate(`/design-configuration/versions/${v.id}`)}>
                                <td className="dc-cell-strong">v{v.version_number}</td>
                                <td>{v.notes || "—"}</td>
                                <td>{v.created_at ? new Date(v.created_at).toLocaleString() : "—"}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {showNewVersion && (
                <div className="dc-modal-backdrop" onClick={() => setShowNewVersion(false)}>
                    <div className="dc-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>New version</h3>
                        <div className="dc-field">
                            <label>Clone from</label>
                            <select value={cloneFrom} onChange={(e) => setCloneFrom(e.target.value)}>
                                <option value="">Start empty</option>
                                {versions.map((v) => (
                                    <option key={v.id} value={v.id}>v{v.version_number}</option>
                                ))}
                            </select>
                        </div>
                        <div className="dc-field">
                            <label>Notes</label>
                            <textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
                        </div>
                        <div className="dc-modal-actions">
                            <button className="dc-btn" onClick={() => setShowNewVersion(false)}>Cancel</button>
                            <button className="dc-btn dc-btn-primary" onClick={handleCreateVersion}>Create</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DesignDetail;
