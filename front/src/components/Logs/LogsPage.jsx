import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchAllLogs,
    clearLogs,
    dismissClearResult,
} from "../../store/logsSlice.js";
import { Pagination } from "./Pagination.jsx";
import "../../assets/LogsPage.css";

/* DELETE /api/logs/clear keys -> the Section names this page shows, so the
   summary line matches the table's own labels. */
const SECTION_LABELS = {
    login: "Login",
    asset: "Asset Management",
    asset_requirement: "Asset Requirement",
    discovery: "Auto Discovery",
    hardening: "Hardening",
};

export const LogsPage = () => {
    const dispatch = useDispatch();
    const { items, isLoading, isClearing, clearError, clearResult } =
        useSelector((state) => state.logs);

    const [sortDirection, setSortDirection] = useState("desc");
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    useEffect(() => {
        dispatch(fetchAllLogs());
    }, [dispatch]);

    // Deleting every log row cannot be undone, so confirm first. Name the
    // sections that survive: the server keeps audit_logs (the tamper-evidence
    // record of privileged actions), which is what the feed labels "Auditing",
    // so those rows stay on screen afterwards and otherwise look like a failure.
    const handleClearHistory = () => {
        const ok = window.confirm(
            "Permanently delete all Login, Asset Management, Asset Requirement, " +
            "Auto Discovery and Hardening log entries?\n\n" +
            "This cannot be undone.\n\n" +
            "Entries in the Auditing section are NOT deleted — they are the " +
            "security audit trail and are kept on purpose, so they will still " +
            "be listed after this."
        );
        if (ok) dispatch(clearLogs());
    };

    const handleRefresh = () => {
        dispatch(fetchAllLogs());
    };

    const handleSort = () => {
        setSortDirection((prev) => (prev === "desc" ? "asc" : "desc"));
        setPage(1);
    };

    const sortedItems = [...items].sort((a, b) => {
        const diff = new Date(b.timestamp) - new Date(a.timestamp);
        return sortDirection === "desc" ? diff : -diff;
    });

    // Logs are merged from six endpoints and sorted here, so paging is
    // client-side; a server page would only cover one source.
    const totalPages = Math.max(1, Math.ceil(sortedItems.length / pageSize));
    const currentPage = Math.min(page, totalPages);
    const pageItems = sortedItems.slice(
        (currentPage - 1) * pageSize,
        currentPage * pageSize
    );

    const formatTimestamp = (ts) => {
        if (!ts) return "-";
        const d = new Date(ts);
        return d.toLocaleString("en-US", {
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
        });
    };

    const getStatusClass = (status) => {
        if (status === "success") return "success";
        if (status === "partial") return "partial";
        if (status === "failed" || status === "failure") return "failed";
        return "unknown";
    };

    const getStatusLabel = (status) => {
        if (status === "success") return "Successful";
        if (status === "partial") return "Partial";
        if (status === "failed" || status === "failure") return "Fail";
        return "Unknown";
    };

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    return (
        <div className="logs-wrapper">

            {/* Toolbar */}
            <div className="logs-toolbar">
                <button
                    className="logs-btn-clear"
                    onClick={handleClearHistory}
                    disabled={isClearing}
                >
                    <i className="fa-solid fa-trash"></i>
                    {isClearing ? "Clearing…" : "Clear History"}
                </button>

                {/* Refresh used to appear only after a "clear"; it is useful on
                    every visit, since the feed is a point-in-time snapshot. */}
                <button className="logs-btn-refresh" onClick={handleRefresh}>
                    <i className="fa-solid fa-rotate-right"></i>
                    Refresh
                </button>

                <button className="logs-btn-sort" onClick={handleSort}>
                    <i className={
                        sortDirection === "desc"
                            ? "fa-solid fa-arrow-down-wide-short"
                            : "fa-solid fa-arrow-up-wide-short"
                    } />
                    Sort by
                </button>
            </div>

            {/* Report the actual per-table counts. Without this the page looks
                unchanged when the only rows left are the preserved Auditing
                ones, which reads as "the button did nothing". */}
            {clearResult && (
                <div className="logs-clear-notice" role="status">
                    <button
                        type="button"
                        className="logs-clear-notice-close"
                        onClick={() => dispatch(dismissClearResult())}
                        aria-label="Dismiss"
                    >
                        ×
                    </button>
                    <strong>
                        Cleared {clearResult.total_deleted ?? 0} log{" "}
                        {clearResult.total_deleted === 1 ? "entry" : "entries"}.
                    </strong>
                    {clearResult.deleted && (
                        <span className="logs-clear-notice-detail">
                            {" "}
                            {Object.entries(clearResult.deleted)
                                .map(([k, v]) => `${SECTION_LABELS[k] || k}: ${v}`)
                                .join(" · ")}
                        </span>
                    )}
                    <div className="logs-clear-notice-detail">
                        Entries in the <strong>Auditing</strong> section are the
                        security audit trail and are kept on purpose — they are
                        still listed below.
                    </div>
                </div>
            )}

            {/* A failed clear must not look like a successful one. */}
            {clearError && (
                <p className="logs-clear-error" role="alert">
                    Could not clear logs: {clearError}
                </p>
            )}

            {/* Table */}
            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th>Number</th>
                        <th>User Name</th>
                        <th>Action</th>
                        <th>Asset Name</th>
                        <th>Section</th>
                        <th>Status</th>
                        <th>Timestamp</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedItems.length === 0 ? (
                        <tr>
                            <td colSpan="7" className="no-data">
                                No logs found
                            </td>
                        </tr>
                    ) : (
                        pageItems.map((item, index) => (
                            <tr key={item.id}>
                                {/* Keep numbering continuous across pages. */}
                                <td>{(currentPage - 1) * pageSize + index + 1}</td>
                                <td>{item.username || "-"}</td>
                                <td>{item.action || "-"}</td>
                                <td>{item.asset_name || "-"}</td>
                                <td>{item.section}</td>
                                <td>
                                    <span className={`logs-status-badge ${getStatusClass(item.status)}`}>
                                        {getStatusLabel(item.status)}
                                    </span>
                                </td>
                                <td className="logs-timestamp">
                                    {formatTimestamp(item.timestamp)}
                                </td>
                            </tr>
                        ))
                    )}
                    </tbody>
                </table>

                <Pagination
                    page={currentPage}
                    pageSize={pageSize}
                    totalItems={sortedItems.length}
                    onPageChange={setPage}
                    onPageSizeChange={(size) => {
                        setPageSize(size);
                        setPage(1);
                    }}
                />
            </div>
        </div>
    );
};