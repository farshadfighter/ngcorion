import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAllLogs, clearLogs } from "../../store/logsSlice";
import "../../assets/Logspage.css";
export const LogsPage = () => {
    const dispatch = useDispatch();
    const { items, isLoading } = useSelector((state) => state.logs);

    const [sortDirection, setSortDirection] = useState("desc");

    useEffect(() => {
        dispatch(fetchAllLogs());
    }, [dispatch]);

    const handleClearHistory = () => {
        dispatch(clearLogs());
    };

    const handleSort = () => {
        setSortDirection((prev) => (prev === "desc" ? "asc" : "desc"));
    };

    const sortedItems = [...items].sort((a, b) => {
        const diff = new Date(b.timestamp) - new Date(a.timestamp);
        return sortDirection === "desc" ? diff : -diff;
    });

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
        return "failed";
    };

    const getStatusLabel = (status) => {
        if (status === "success") return "Successful";
        if (status === "partial") return "Partial";
        return "Fail";
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
                    {sortedItems.length === 0 ? (
                        <tr>
                            <td colSpan="7" className="no-data">
                                No logs found
                            </td>
                        </tr>
                    ) : (
                        sortedItems.map((item, index) => (
                            <tr key={item.id}>
                                <td>{index + 1}</td>
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
        </div>
    );
};