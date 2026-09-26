import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams, useNavigate } from "react-router-dom";
import {
    fetchHostDetail,
    setHostCredential,
    deleteHostCredential,
    pollHostNow,
    fetchHostMetric,
    clearMessages,
} from "../../store/nocSlice.jsx";
import { MetricChart } from "../shared/MetricChart.jsx";
import { TimeRangePicker } from "../shared/TimeRangePicker.jsx";
import "../../assets/Noc.css";

function formatUptime(ticks) {
    if (ticks == null) return "—";
    const totalSeconds = Math.floor(ticks / 100); // sysUpTime is in hundredths of a second
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
}

function formatBytes(n) {
    if (n == null) return "—";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
    return `${value.toFixed(1)} ${units[i]}`;
}

// IF-MIB ifType values (RFC 2863 / the IANAifType-MIB registry) an interface
// reports over SNMP - a real device's ifTable is rarely just physical ports:
// FortiGate alone routinely reports VLANs, LACP aggregates and IPsec/GRE
// tunnels alongside the front-panel ports, often with no ifDescr set on the
// non-physical ones. Grouping by this (not by whether ifDescr happens to be
// blank) is what turns "47 unlabeled rows" into something a human can scan.
const IF_TYPE_GROUPS = {
    Physical: new Set([6, 7, 62, 69, 117, 175, 176, 237, 243, 244]), // ethernetCsmacd, gigabitEthernet, etc.
    VLAN: new Set([135, 136]), // l2vlan, l3ipvlan
    Aggregate: new Set([161]), // ieee8023adLag
    Tunnel: new Set([131, 150, 23, 118]), // tunnel, mpls, ppp, gre-ish propVirtual variants
};

function classifyInterfaceType(ifType) {
    for (const [group, codes] of Object.entries(IF_TYPE_GROUPS)) {
        if (codes.has(ifType)) return group;
    }
    return "Other";
}

const INTERFACE_FILTERS = ["All", "Physical", "VLAN", "Aggregate", "Tunnel", "Other"];

export const NocHostDetail = () => {
    const { assetId } = useParams();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { currentHost, isPolling, error, successMessage, metricSeries, isLoadingMetric } = useSelector((state) => state.noc);

    const [interfaceFilter, setInterfaceFilter] = useState("All");

    const [historyMetric, setHistoryMetric] = useState("reachable");
    const [historyInterfaceId, setHistoryInterfaceId] = useState(null);
    const [historyRange, setHistoryRange] = useState(() => {
        const to = new Date();
        const from = new Date(to.getTime() - 24 * 3600 * 1000);
        return { from: from.toISOString(), to: to.toISOString(), label: "24h" };
    });

    const [version, setVersion] = useState("v2c");
    const [port, setPort] = useState(161);
    const [community, setCommunity] = useState("");
    const [username, setUsername] = useState("");
    const [authProtocol, setAuthProtocol] = useState("SHA");
    const [authKey, setAuthKey] = useState("");
    const [privProtocol, setPrivProtocol] = useState("AES");
    const [privKey, setPrivKey] = useState("");

    // Pre-fill the form from the fetched credential. Adjusted during render
    // (not in an effect - see https://react.dev/learn/you-might-not-need-an-effect)
    // by tracking the last credential object this component reacted to, so a
    // genuinely new fetch result (new object reference from redux) updates
    // the form exactly once instead of looping through an extra render.
    const [seenCredential, setSeenCredential] = useState(undefined);
    if (currentHost?.credential !== undefined && currentHost.credential !== seenCredential) {
        setSeenCredential(currentHost.credential);
        if (currentHost.credential) {
            setVersion(currentHost.credential.version);
            setPort(currentHost.credential.port);
            setUsername(currentHost.credential.username || "");
            setAuthProtocol(currentHost.credential.auth_protocol || "SHA");
            setPrivProtocol(currentHost.credential.priv_protocol || "AES");
        }
    }

    useEffect(() => {
        dispatch(fetchHostDetail(assetId));
    }, [dispatch, assetId]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    // Derived, not stored: defaults to the first interface once they load,
    // for the traffic metrics (device-level "reachable" needs none) - an
    // explicit user pick in historyInterfaceId always wins.
    const effectiveInterfaceId = historyInterfaceId ?? currentHost?.interfaces?.[0]?.id ?? null;

    useEffect(() => {
        if (historyMetric !== "reachable" && effectiveInterfaceId === null) return;
        dispatch(fetchHostMetric({
            assetId,
            metric: historyMetric,
            interfaceId: historyMetric === "reachable" ? null : effectiveInterfaceId,
            from: historyRange.from,
            to: historyRange.to,
        }));
    }, [dispatch, assetId, historyMetric, effectiveInterfaceId, historyRange]);

    if (!currentHost) {
        return <div className="noc-container"><div className="noc-empty">Loading…</div></div>;
    }

    const handleSaveCredential = () => {
        const payload = { version, port: Number(port) };
        if (version === "v2c") {
            payload.community = community || undefined;
        } else {
            payload.username = username;
            payload.auth_protocol = authProtocol;
            payload.auth_key = authKey || undefined;
            payload.priv_protocol = privProtocol;
            payload.priv_key = privKey || undefined;
        }
        dispatch(setHostCredential({ assetId, payload })).then(() => {
            setCommunity("");
            setAuthKey("");
            setPrivKey("");
        });
    };

    const statusKey = !currentHost.credential ? "unmonitored" : currentHost.reachable ? "up" : "down";

    return (
        <div className="noc-container">
            <div className="noc-toolbar">
                <button className="noc-btn" onClick={() => navigate("/noc/hosts")}>
                    <i className="fa-solid fa-arrow-left" /> Back to hosts
                </button>
                <button
                    className="noc-btn noc-btn-primary"
                    onClick={() => dispatch(pollHostNow(assetId))}
                    disabled={isPolling || !currentHost.credential}
                    title={!currentHost.credential ? "Configure an SNMP credential first" : undefined}
                >
                    <i className="fa-solid fa-arrows-rotate" /> {isPolling ? "Polling…" : "Poll Now"}
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`noc-toast ${error ? "noc-toast-error" : "noc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="noc-detail-grid">
                <div>
                    <div className="noc-card">
                        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                            <h3 style={{ margin: 0 }}>{currentHost.asset_name}</h3>
                            <span className={`noc-status-pill ${statusKey}`}>
                                <span className={`noc-status-dot ${statusKey}`} />
                                {statusKey === "unmonitored" ? "Not monitored" : statusKey === "up" ? "Reachable" : "Unreachable"}
                            </span>
                        </div>
                        <dl className="noc-kv-grid">
                            <dt>Type</dt><dd>{currentHost.asset_type_name || "—"}</dd>
                            <dt>IP Address</dt><dd>{currentHost.ip_address || "—"}</dd>
                            <dt>Last Polled</dt><dd>{currentHost.last_polled_at ? new Date(currentHost.last_polled_at).toLocaleString() : "Never"}</dd>
                            {currentHost.error_message && (<><dt>Error</dt><dd>{currentHost.error_message}</dd></>)}
                        </dl>
                    </div>

                    <div className="noc-card">
                        <h3>SNMP System Info</h3>
                        <dl className="noc-kv-grid">
                            <dt>sysDescr</dt><dd>{currentHost.sys_descr || "—"}</dd>
                            <dt>sysName</dt><dd>{currentHost.sys_name || "—"}</dd>
                            <dt>sysContact</dt><dd>{currentHost.sys_contact || "—"}</dd>
                            <dt>sysLocation</dt><dd>{currentHost.sys_location || "—"}</dd>
                            <dt>Uptime</dt><dd>{formatUptime(currentHost.sys_uptime_ticks)}</dd>
                        </dl>
                    </div>

                    <div className="noc-card">
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
                            <h3 style={{ margin: 0 }}>History</h3>
                            <div style={{ display: "flex", gap: 6 }}>
                                <select
                                    value={historyMetric}
                                    onChange={(e) => setHistoryMetric(e.target.value)}
                                    className="noc-mini-select"
                                >
                                    <option value="reachable">Reachability</option>
                                    <option value="if_in_octets">Interface — In traffic</option>
                                    <option value="if_out_octets">Interface — Out traffic</option>
                                </select>
                                {historyMetric !== "reachable" && (
                                    <select
                                        value={effectiveInterfaceId ?? ""}
                                        onChange={(e) => setHistoryInterfaceId(Number(e.target.value))}
                                        className="noc-mini-select"
                                    >
                                        {currentHost.interfaces.map((iface) => (
                                            <option key={iface.id} value={iface.id}>{iface.if_descr || `#${iface.if_index}`}</option>
                                        ))}
                                    </select>
                                )}
                            </div>
                        </div>
                        <div style={{ margin: "10px 0" }}>
                            <TimeRangePicker value={historyRange} onChange={setHistoryRange} dark />
                        </div>
                        {isLoadingMetric ? (
                            <div className="noc-empty">Loading…</div>
                        ) : (
                            <MetricChart
                                points={metricSeries?.points}
                                color={historyMetric === "reachable" ? "#34d399" : "#2dd4bf"}
                                valueFormatter={(v) =>
                                    historyMetric === "reachable" ? (v >= 0.5 ? "up" : "down") : formatBytes(v)
                                }
                                dark
                            />
                        )}
                        {metricSeries?.granularity && metricSeries.granularity !== "raw" && (
                            <div style={{ fontSize: 10.5, color: "#5c667e", marginTop: 6 }}>
                                Averaged into {metricSeries.granularity} buckets for this range.
                            </div>
                        )}
                    </div>

                    <div className="noc-card">
                        {(() => {
                            const grouped = currentHost.interfaces.map((iface) => ({
                                ...iface,
                                _group: classifyInterfaceType(iface.if_type),
                            }));
                            const counts = INTERFACE_FILTERS.reduce((acc, f) => {
                                acc[f] = f === "All" ? grouped.length : grouped.filter((i) => i._group === f).length;
                                return acc;
                            }, {});
                            const visible = interfaceFilter === "All" ? grouped : grouped.filter((i) => i._group === interfaceFilter);

                            return (
                                <>
                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10, marginBottom: 14 }}>
                                        <h3 style={{ margin: 0 }}>Interfaces</h3>
                                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                                            {INTERFACE_FILTERS.filter((f) => f === "All" || counts[f] > 0).map((f) => (
                                                <button
                                                    key={f}
                                                    type="button"
                                                    className={`noc-chip ${interfaceFilter === f ? "noc-chip-active" : ""}`}
                                                    onClick={() => setInterfaceFilter(f)}
                                                >
                                                    {f} ({counts[f]})
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                    {grouped.length === 0 ? (
                                        <div className="noc-empty">No interface data yet — poll this host to fetch it.</div>
                                    ) : (
                                        <table className="noc-table">
                                            <thead>
                                                <tr>
                                                    <th>#</th>
                                                    <th>Description</th>
                                                    <th>Type</th>
                                                    <th>Speed</th>
                                                    <th>Admin</th>
                                                    <th>Oper</th>
                                                    <th>In</th>
                                                    <th>Out</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {visible.map((iface) => (
                                                    <tr key={iface.if_index}>
                                                        <td>{iface.if_index}</td>
                                                        <td>{iface.if_descr || "—"}</td>
                                                        <td style={{ color: "#8b96ac" }}>{iface._group}</td>
                                                        <td>{iface.if_speed ? `${(iface.if_speed / 1e6).toFixed(0)} Mbps` : "—"}</td>
                                                        <td style={{ color: iface.if_admin_status === "up" ? "#34d399" : undefined }}>{iface.if_admin_status || "—"}</td>
                                                        <td style={{ color: iface.if_oper_status === "up" ? "#34d399" : iface.if_oper_status === "down" ? "#f87171" : undefined }}>{iface.if_oper_status || "—"}</td>
                                                        <td>{formatBytes(iface.in_octets)}</td>
                                                        <td>{formatBytes(iface.out_octets)}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                </>
                            );
                        })()}
                    </div>
                </div>

                <div className="noc-card">
                    <h3>SNMP Credential</h3>
                    <div className="noc-field">
                        <label>Version</label>
                        <select value={version} onChange={(e) => setVersion(e.target.value)}>
                            <option value="v2c">v2c</option>
                            <option value="v3">v3</option>
                        </select>
                    </div>
                    <div className="noc-field">
                        <label>Port</label>
                        <input type="number" value={port} onChange={(e) => setPort(e.target.value)} />
                    </div>

                    {version === "v2c" ? (
                        <div className="noc-field">
                            <label>Community String</label>
                            <input
                                type="password"
                                value={community}
                                onChange={(e) => setCommunity(e.target.value)}
                                placeholder={currentHost.credential?.has_community ? "•••••••• (set — enter to replace)" : "e.g. public"}
                            />
                        </div>
                    ) : (
                        <>
                            <div className="noc-field">
                                <label>Username</label>
                                <input value={username} onChange={(e) => setUsername(e.target.value)} />
                            </div>
                            <div className="noc-field">
                                <label>Auth Protocol</label>
                                <select value={authProtocol} onChange={(e) => setAuthProtocol(e.target.value)}>
                                    <option value="SHA">SHA</option>
                                    <option value="MD5">MD5</option>
                                </select>
                            </div>
                            <div className="noc-field">
                                <label>Auth Key</label>
                                <input
                                    type="password"
                                    value={authKey}
                                    onChange={(e) => setAuthKey(e.target.value)}
                                    placeholder={currentHost.credential?.has_auth_key ? "•••••••• (set — enter to replace)" : ""}
                                />
                            </div>
                            <div className="noc-field">
                                <label>Priv Protocol</label>
                                <select value={privProtocol} onChange={(e) => setPrivProtocol(e.target.value)}>
                                    <option value="AES">AES</option>
                                    <option value="DES">DES</option>
                                </select>
                            </div>
                            <div className="noc-field">
                                <label>Priv Key</label>
                                <input
                                    type="password"
                                    value={privKey}
                                    onChange={(e) => setPrivKey(e.target.value)}
                                    placeholder={currentHost.credential?.has_priv_key ? "•••••••• (set — enter to replace)" : ""}
                                />
                            </div>
                        </>
                    )}

                    <div className="noc-credential-actions">
                        <button className="noc-btn noc-btn-primary" onClick={handleSaveCredential}>Save</button>
                        {currentHost.credential && (
                            <button className="noc-btn noc-btn-danger" onClick={() => dispatch(deleteHostCredential(assetId))}>
                                Remove
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NocHostDetail;
