import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchAuditSessions,
    deleteAuditSession,
    clearMessages,
} from "../../store/auditSlice";
import { AuditingWizard } from "./AuditingWizard";
import { AuditingResultModal } from "./AuditingResultModal";
import "../../assets/Auditing.css";

export const AuditingList = () => {
    const dispatch = useDispatch();
    const { sessions, isLoading, error, successMessage } = useSelector(
        (state) => state.audit
    );

    const [showWizard, setShowWizard] = useState(false);
    const [showResultModal, setShowResultModal] = useState(false);
    const [selectedSession, setSelectedSession] = useState(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [sessionToDelete, setSessionToDelete] = useState(null);
    const [deleteError, setDeleteError] = useState(null);

    // Local storage for job names (since backend doesn't store them)
    const [jobNames, setJobNames] = useState(() => {
        const stored = localStorage.getItem("auditJobNames");
        return stored ? JSON.parse(stored) : {};
    });

    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    const handleDeleteClick = (session) => {
        setSessionToDelete(session);
        setShowDeleteModal(true);
        setDeleteError(null); // Reset error
    };

    const handleDeleteConfirm = async () => {
        if (sessionToDelete) {
            try {
                // انجام delete و منتظر ماندن برای نتیجه
                await dispatch(deleteAuditSession(sessionToDelete.session_id)).unwrap();

                // فقط اگه موفق بود، از localStorage پاک کن
                const newJobNames = { ...jobNames };
                delete newJobNames[sessionToDelete.session_id];
                setJobNames(newJobNames);
                localStorage.setItem("auditJobNames", JSON.stringify(newJobNames));

                setShowDeleteModal(false);
                setSessionToDelete(null);
                setDeleteError(null);

                // Refresh لیست sessions
                dispatch(fetchAuditSessions());
            } catch (error) {
                // نمایش خطا به کاربر
                const errorMessage = error?.message || error?.toString() || "Failed to delete session";
                setDeleteError(errorMessage);
                console.error("Delete failed:", error);
            }
        }
    };

    const handleSeeResult = (session) => {
        setSelectedSession(session);
        setShowResultModal(true);
    };

    const handleWizardComplete = (sessionId, jobName) => {
        // Save job name to local storage
        const newJobNames = { ...jobNames, [sessionId]: jobName };
        setJobNames(newJobNames);
        localStorage.setItem("auditJobNames", JSON.stringify(newJobNames));

        setShowWizard(false);
        dispatch(fetchAuditSessions());
    };

    const getStatusBadge = (status) => {
        if (status === "completed") {
            return <span className="status-badge status-success">Successful</span>;
        } else if (status === "failed") {
            return <span className="status-badge status-failed">Failed</span>;
        } else if (status === "running") {
            return <span className="status-badge status-running">Running</span>;
        } else {
            return <span className="status-badge status-unknown">{status}</span>;
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        const date = new Date(dateString);
        return date.toLocaleString("en-US", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
        });
    };

    return (
        <div className="auditing-container">
            {/* Header */}
            <div className="auditing-header">
                <button
                    className="btn-auditing-primary"
                    onClick={() => setShowWizard(true)}
                >
                    <img src="/icons/audit.svg" alt="" className="btn-icon" />
                    Auditing
                </button>
            </div>

            {/* Alerts */}
            {successMessage && (
                <div className="alert alert-success">{successMessage}</div>
            )}
            {error && <div className="alert alert-error">{error}</div>}

            {/* Table */}
            <div className="auditing-table-wrapper">
                {isLoading ? (
                    <div className="loading-spinner">Loading audit sessions...</div>
                ) : (
                    <table className="auditing-table">
                        <thead>
                        <tr>
                            <th>Job Name</th>
                            <th>Asset Name</th>
                            <th>Process</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        {sessions && sessions.length > 0 ? (
                            sessions.map((session) => (
                                <tr key={session.session_id}>
                                    <td>{jobNames[session.session_id] || `job number${session.session_id}`}</td>
                                    <td>{session.asset_name || "-"}
                                        {session.target_ip && ` (${session.target_ip})`}</td>
                                    <td>{getStatusBadge(session.status)}</td>
                                    <td>{formatDate(session.started_at)}</td>
                                    <td>
                                        <div className="table-actions">
                                            <div style={{ minWidth: '140px' }}>
                                                {session.status === "completed" && (
                                                    <button
                                                        className="btn-see-result"
                                                        onClick={() => handleSeeResult(session)}
                                                    >
                                                        <img src="/icons/audit.svg" alt="" className="btn-action-icon" />
                                                        See Result
                                                    </button>
                                                )}
                                            </div>
                                            <button
                                                className="btn-delete-icon"
                                                onClick={() => handleDeleteClick(session)}
                                                title="Delete"
                                            >
                                                <img src={"/icons/delete.svg"} alt={"delete"} />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="5" style={{ textAlign: "center", padding: "40px" }}>
                                    No audit sessions found. Click "Auditing" to start a new audit.
                                </td>
                            </tr>
                        )}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Delete Confirmation Modal */}
            {showDeleteModal && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button
                                className="modal-close"
                                onClick={() => setShowDeleteModal(false)}
                            >
                                ✕
                            </button>
                        </div>
                        <div className="modal-body">
                            <p>
                                Are you sure you want to delete this audit session?
                            </p>
                            <p style={{ color: "#dc3545", fontSize: "13px", marginTop: "8px" }}>
                                This action cannot be undone.
                            </p>
                            {deleteError && (
                                <div className="alert alert-error" style={{ marginTop: "12px" }}>
                                    {deleteError}
                                </div>
                            )}
                        </div>
                        <div className="modal-actions">
                            <button
                                className="btn-cancel"
                                onClick={() => setShowDeleteModal(false)}
                            >
                                Cancel
                            </button>
                            <button className="btn-delete2" onClick={handleDeleteConfirm}>
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Wizard Modal */}
            {showWizard && (
                <AuditingWizard
                    isOpen={showWizard}
                    onClose={() => setShowWizard(false)}
                    onComplete={handleWizardComplete}
                />
            )}

            {/* Result Modal */}
            {showResultModal && selectedSession && (
                <AuditingResultModal
                    session={selectedSession}
                    isOpen={showResultModal}
                    onClose={() => {
                        setShowResultModal(false);
                        setSelectedSession(null);
                    }}
                />
            )}
        </div>
    );
};