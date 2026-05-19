import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAllLogs, clearLogs } from "../../store/logsSlice.js";
import "../../assets/LogsPage.css";

const PAGE_SIZE = 50;

export const LogsPage = () => {
    const dispatch = useDispatch();
    const { items, isLoading, isCleared } = useSelector((state) => state.logs);

    const [sortDirection, setSortDirection] = useState("desc");
    const [currentPage, setCurrentPage] = useState(1);

    useEffect(() => {
        if (!isCleared) {
            dispatch(fetchAllLogs());
        }
    }, [dispatch, isCleared]);

    // reset page when items change
    useEffect(() => {
        setCurrentPage(1);
    }, [items]);

    const handleClearHistory = () => {
        dispatch(clearLogs());
        setCurrentPage(1);
    };

    const handleRefresh = () => {
        dispatch(fetchAllLogs());
        setCurrentPage(1);
    };

    const handleSort = () => {
        setSortDirection((prev) => (prev === "desc" ? "asc" : "desc"));
        setCurrentPage(1);
    };

    const sortedItems = [...items].sort((a, b) => {
        const diff = new Date(b.timestamp) - new Date(a.timestamp);
        return sortDirection === "desc" ? diff : -diff;
    });

    const totalPages = Math.ceil(sortedItems.length / PAGE_SIZE);
    const paginatedItems = sortedItems.slice(
        (currentPage - 1) * PAGE_SIZE,
        currentPage * PAGE_SIZE
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
                <button className="logs-btn-clear" onClick={handleClearHistory}>
                    <i className="fa-solid fa-trash"></i>
                    Clear History
                </button>

                {isCleared && (
                    <button className="logs-btn-refresh" onClick={handleRefresh}>
                        <i className="fa-solid fa-rotate-right"></i>
                        Refresh
                    </button>
                )}

                <button className="logs-btn-sort" onClick={handleSort}>
                    <i
                        className={
                            sortDirection === "desc"
                                ? "fa-solid fa-arrow-down-wide-short"
                                : "fa-solid fa-arrow-up-wide-short"
                        }
                    />
                    Sort by
                </button>
            </div>

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
                    {paginatedItems.length === 0 ? (
                        <tr>
                            <td colSpan="7" className="no-data">
                                No logs found
                            </td>
                        </tr>
                    ) : (
                        paginatedItems.map((item, index) => (
                            <tr key={item.id}>
                                <td>{(currentPage - 1) * PAGE_SIZE + index + 1}</td>
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
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="logs-pagination">
                    <span className="logs-pagination-info">
                        Showing {(currentPage - 1) * PAGE_SIZE + 1}–{Math.min(currentPage * PAGE_SIZE, sortedItems.length)} of {sortedItems.length}
                    </span>
                    <div className="logs-pagination-buttons">
                        <button
                            className="logs-page-btn"
                            onClick={() => setCurrentPage(1)}
                            disabled={currentPage === 1}
                        >
                            <i className="fa-solid fa-angles-left" />
                        </button>
                        <button
                            className="logs-page-btn"
                            onClick={() => setCurrentPage((p) => p - 1)}
                            disabled={currentPage === 1}
                        >
                            <i className="fa-solid fa-angle-left" />
                        </button>

                        <span className="logs-page-current">
                            {currentPage} / {totalPages}
                        </span>

                        <button
                            className="logs-page-btn"
                            onClick={() => setCurrentPage((p) => p + 1)}
                            disabled={currentPage === totalPages}
                        >
                            <i className="fa-solid fa-angle-right" />
                        </button>
                        <button
                            className="logs-page-btn"
                            onClick={() => setCurrentPage(totalPages)}
                            disabled={currentPage === totalPages}
                        >
                            <i className="fa-solid fa-angles-right" />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};