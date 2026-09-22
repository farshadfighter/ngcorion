import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { fetchHosts, clearMessages } from "../../store/nocSlice.jsx";
import { Pagination } from "../Logs/Pagination.jsx";
import "../../assets/Noc.css";
// Pagination's styles live with the Logs page it was first built for (see
// AssetList.jsx, which reuses it the same way).
import "../../assets/LogsPage.css";

export const NocHostList = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { hosts, isLoading, error, successMessage } = useSelector((state) => state.noc);
    const [search, setSearch] = useState("");
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    useEffect(() => {
        dispatch(fetchHosts());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        if (!q) return hosts;
        return hosts.filter(
            (h) =>
                h.asset_name.toLowerCase().includes(q) ||
                (h.ip_address || "").toLowerCase().includes(q) ||
                (h.asset_type_name || "").toLowerCase().includes(q)
        );
    }, [hosts, search]);

    // Client-side: /api/noc/hosts returns every asset and the search above
    // already operates on the full list (same pattern as AssetList.jsx).
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    const safePage = Math.min(page, totalPages);
    const paged = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

    // A search that shrinks the list can leave the current page past the end.
    useEffect(() => {
        if (page > totalPages) setPage(1);
    }, [totalPages, page]);

    return (
        <div className="noc-container">
            <div className="noc-toolbar">
                <div className="noc-toolbar-info">{filtered.length} of {hosts.length} asset(s)</div>
                <input
                    placeholder="Search by name, IP or type…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    style={{ padding: "8px 12px", border: "1px solid #e5e7eb", borderRadius: 8, fontSize: 13, minWidth: 260 }}
                />
            </div>

            {(error || successMessage) && (
                <div className={`noc-toast ${error ? "noc-toast-error" : "noc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="noc-table-container">
                {isLoading ? (
                    <div className="noc-empty">Loading…</div>
                ) : filtered.length === 0 ? (
                    <div className="noc-empty">No matching assets.</div>
                ) : (
                    <table className="noc-table">
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Asset</th>
                                <th>Type</th>
                                <th>IP Address</th>
                                <th>SNMP Monitoring</th>
                                <th>Last Polled</th>
                            </tr>
                        </thead>
                        <tbody>
                            {paged.map((h) => {
                                const statusKey = !h.has_credential ? "unmonitored" : h.reachable ? "up" : "down";
                                return (
                                    <tr key={h.asset_id} className="clickable" onClick={() => navigate(`/noc/hosts/${h.asset_id}`)}>
                                        <td><span className={`noc-status-dot ${statusKey}`} />{statusKey === "unmonitored" ? "Not monitored" : statusKey === "up" ? "Up" : "Down"}</td>
                                        <td>{h.asset_name}</td>
                                        <td>{h.asset_type_name || "—"}</td>
                                        <td>{h.ip_address || "—"}</td>
                                        <td>{h.has_credential ? "Configured" : "Not configured"}</td>
                                        <td>{h.last_polled_at ? new Date(h.last_polled_at).toLocaleString() : "—"}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>

            <Pagination
                page={safePage}
                pageSize={pageSize}
                totalItems={filtered.length}
                onPageChange={setPage}
                onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
            />
        </div>
    );
};

export default NocHostList;
