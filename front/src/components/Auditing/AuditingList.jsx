import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useParams } from "react-router-dom";
import {
    fetchAuditSessions,
    deleteAuditSession,
    clearAllAuditSessions,
    clearMessages,
} from "../../store/auditSlice";
import { AuditingWizard } from "./AuditingWizard";
import { AuditingResultModal } from "./AuditingResultModal";
import { LicenseLimitModal } from "../License/LicenseLimitModal";
import { getLicenseStatusThunk } from "../../store/licenseSlice";
import { getDeviceName } from "../../store/hardeningSlice";

import "../../assets/Auditing.css";

export const AuditingList = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { sessionId } = useParams();
    const { usage, limits } = useSelector((state) => state.license);
    const [showLimitModal, setShowLimitModal] = useState(false);

    const isAuditLimitReached =
        limits?.max_audits !== null &&
        (usage?.used_audits ?? 0) >= (limits?.max_audits ?? 0);

    const { sessions, isLoading, isClearing, error, successMessage } = useSelector(
        (state) => state.audit
    );

    const [showWizard, setShowWizard] = useState(false);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    // Paged client-side: the sessions list is already in the store. Clamped
    // while rendering so a shrinking list cannot strand the user on a page
    // that no longer exists.
    const totalSessions = sessions?.length || 0;
    const safePage = Math.min(page, Math.max(1, Math.ceil(totalSessions / pageSize)));
    const pagedSessions = (sessions || []).slice(
        (safePage - 1) * pageSize,
        safePage * pageSize
    );

    // The open result modal is derived from the URL (:sessionId) rather than
    // stored in state, so a deep link and a click behave identically.
    const selectedSession = sessionId && sessions
        ? sessions.find((s) => String(s.session_id) === String(sessionId))
        : null;
    const showResultModal = Boolean(selectedSession);

    // Delete single
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [sessionToDelete, setSessionToDelete] = useState(null);
    const [deleteError, setDeleteError] = useState(null);

    // Clear history
    const [showClearModal, setShowClearModal] = useState(false);
    const [clearError, setClearError] = useState(null);

    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    // ── Delete single ──────────────────────────────────────────────────────────
    const handleDeleteClick = (session) => {
        setSessionToDelete(session);
        setShowDeleteModal(true);
        setDeleteError(null);
    };

    const handleDeleteConfirm = async () => {
        if (!sessionToDelete) return;
        try {
            await dispatch(deleteAuditSession(sessionToDelete.session_id)).unwrap();
            setShowDeleteModal(false);
            setSessionToDelete(null);
            setDeleteError(null);
            dispatch(fetchAuditSessions());
        } catch (err) {
            setDeleteError(err?.message || err?.toString() || "Failed to delete session");
        }
    };

    // ── Clear all history ──────────────────────────────────────────────────────
    const handleClearHistoryClick = () => {
        setClearError(null);
        setShowClearModal(true);
    };

    const handleClearConfirm = async () => {
        try {
            await dispatch(clearAllAuditSessions()).unwrap();
            setShowClearModal(false);
            setClearError(null);
        } catch (err) {
            setClearError(err?.message || err?.toString() || "Failed to clear history");
        }
    };

    // Deep-link guard: if the URL points at a session id that doesn't exist
    // (once sessions have loaded), fall back to the plain list URL.
    useEffect(() => {
        if (sessionId && sessions && sessions.length > 0 && !selectedSession) {
            navigate("/audit/sessions", { replace: true });
        }
    }, [sessionId, sessions, selectedSession, navigate]);

    // ── Misc ──────────────────────────────────────────────────────────────────
    // Navigating updates the URL, which derives the open modal above — so a deep
    // link and a click land in exactly the same state.
    const handleSeeResult = (session) => {
        navigate(`/audit/sessions/${session.session_id}`);
    };

    const handleCloseResult = () => {
        navigate("/audit/sessions");
    };

    const handleNavigateToLicence = () => navigate("/settings/license");

    const handleWizardComplete = () => {
        setShowWizard(false);
        dispatch(fetchAuditSessions());
        dispatch(getLicenseStatusThunk());
    };

    const getStatusBadge = (status) => {
        if (status === "completed") return <span className="status-badge status-success">Successful</span>;
        if (status === "failed")    return <span className="status-badge status-failed">Failed</span>;
        if (status === "running")   return <span className="status-badge status-running">Running</span>;
        return <span className="status-badge status-unknown">{status}</span>;
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        return new Date(dateString).toLocaleString("en-US", {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit",
        });
    };

    const primaryColor = "#1e3a5f";

    return (
        <div className="auditing-container">
            {/* Header */}
            <div className="auditing-header" style={{ display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
                <button
                    className="btn-auditing-primary"
                    onClick={() => isAuditLimitReached ? setShowLimitModal(true) : setShowWizard(true)}
                    disabled={isAuditLimitReached}
                    title={isAuditLimitReached ? "Audit limit reached" : ""}
                    style={{ opacity: isAuditLimitReached ? 0.6 : 1, cursor: isAuditLimitReached ? "not-allowed" : "pointer" }}
                >
                    <img src="/icons/audit.svg" alt="" className="btn-icon" />
                  Add New Auditing
                </button>

                {/* Clear History */}
                <button
                    className="btn-modal-primary"
                    onClick={handleClearHistoryClick}
                    disabled={sessions.length === 0 || isClearing}
                    style={{
                        position: "absolute",
                        right: 0,
                        opacity: sessions.length === 0 || isClearing ? 0.5 : 1,
                        cursor: sessions.length === 0 || isClearing ? "not-allowed" : "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                    }}
                >
                    <i className="fa-solid fa-trash"></i> Clear History
                </button>
            </div>

            {/* Alerts */}
            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error          && <div className="alert alert-error">{error}</div>}

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
                            <th>Device Type</th>
                            <th>Process</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        {pagedSessions.length > 0 ? (
                            pagedSessions.map((session) => (
                                <tr key={session.session_id}>
                                    <td>{session.job_name || `job number${session.session_id}`}</td>
                                    <td>
                                        {session.asset_name || "-"}
                                        {session.target_ip && ` (${session.target_ip})`}
                                    </td>
                                    <td>{getDeviceName(session.sub_device_type || session.device_type)}</td>
                                    <td>{getStatusBadge(session.status)}</td>
                                    <td>{formatDate(session.started_at)}</td>
                                    <td>
                                        <div className="table-actions">
                                            <div style={{ minWidth: "140px" }}>
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
                                                <i className="fa-solid fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="6" style={{ textAlign: "center", padding: "40px" }}>
                                    No audit sessions found. Click "Auditing" to start a new audit.
                                </td>
                            </tr>
                        )}
                        </tbody>
                    </table>
                )}
            </div>

            <Pagination
                page={safePage}
                pageSize={pageSize}
                totalItems={totalSessions}
                onPageChange={setPage}
                onPageSizeChange={(size) => {
                    setPageSize(size);
                    setPage(1);
                }}
            />

            {/* ── Delete single modal ────────────────────────────────────────────── */}
            {showDeleteModal && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this audit session?</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>
                                This action cannot be undone.
                            </p>
                            {deleteError && (
                                <div className="alert alert-error" style={{ marginTop: "12px" }}>{deleteError}</div>
                            )}
                        </div>
                        <div className="modal-actions">
                            <button className="btn-modal-secondary" onClick={() => setShowDeleteModal(false)}>Cancel</button>
                            <button className="btn-delete2" onClick={handleDeleteConfirm}>Delete</button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Clear History modal ────────────────────────────────────────────── */}
            {showClearModal && (
                <div className="modal-overlay" onClick={() => setShowClearModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header" style={{ borderBottom: `3px solid ${primaryColor}` }}>
                            <h3 style={{ color: primaryColor }}> <i className="fa-solid fa-trash"></i>
                                Clear History</h3>
                            <button className="modal-close" onClick={() => setShowClearModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to clear <strong>all</strong> audit history?</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>
                                This will permanently delete <strong>{sessions.length}</strong> session{sessions.length !== 1 ? "s" : ""}. This action cannot be undone.
                            </p>
                            {clearError && (
                                <div className="alert alert-error" style={{ marginTop: "12px" }}>{clearError}</div>
                            )}
                        </div>
                        <div className="modal-actions">
                            <button className="btn-modal-secondary" onClick={() => setShowClearModal(false)}>
                                Cancel
                            </button>
                            <button
                                className="btn-modal-primary"
                                onClick={handleClearConfirm}
                                disabled={isClearing}
                            >
                                {isClearing ? "Clearing..." : "Yes, Clear All"}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Wizard ────────────────────────────────────────────────────────── */}
            {showWizard && (
                <AuditingWizard
                    isOpen={showWizard}
                    onClose={() => setShowWizard(false)}
                    onComplete={handleWizardComplete}
                />
            )}


            {/* ── Result Modal ──────────────────────────────────────────────────── */}
            {showResultModal && selectedSession && (
                <AuditingResultModal
                    session={selectedSession}
                    isOpen={showResultModal}
                    onClose={handleCloseResult}
                />
            )}

            {/* ── License Limit Modal ───────────────────────────────────────────── */}
            {showLimitModal && (
                <LicenseLimitModal
                    isOpen={showLimitModal}
                    module="auditing"
                    onClose={() => setShowLimitModal(false)}
                    onGoToLicence={() => {
                        setShowLimitModal(false);
                        handleNavigateToLicence();
                    }}
                />
            )}
        </div>
    );
};