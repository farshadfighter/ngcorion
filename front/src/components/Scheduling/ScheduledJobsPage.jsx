import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchScheduledJobs,
    createScheduledJob,
    updateScheduledJob,
    deleteScheduledJob,
    runScheduledJobNow,
    fetchJobRuns,
    clearMessages,
} from "../../store/schedulingSlice.jsx";
import { fetchAssets } from "../../store/assetSlice.jsx";
import { usePermission } from "../../hooks/usePermission";
import { AccessDenied } from "../routePages.jsx";
import "../../assets/Scheduling.css";
import { t as tr, uiLocale } from "../../i18n";

const DAY_NAMES = [tr("Monday"), tr("Tuesday"), tr("Wednesday"), tr("Thursday"), tr("Friday"), tr("Saturday"), tr("Sunday")];

// Windows Server roles connect like Windows Server itself.
const WINRM_FIELDS = [
    { key: "windows_username", label: tr("Windows Username"), type: "text", required: true },
    { key: "windows_password", label: tr("Windows Password"), type: "password", required: true },
    { key: "winrm_port", label: tr("WinRM Port"), type: "number", default: 5985 },
];

const TECH_FIELDS = {
    cisco: [
        { key: "ssh_username", label: tr("SSH Username"), type: "text", required: true },
        { key: "ssh_password", label: tr("SSH Password"), type: "password", required: true },
        { key: "ssh_secret", label: tr("Enable Secret (optional)"), type: "password" },
        { key: "ssh_port", label: tr("SSH Port"), type: "number", default: 22 },
    ],
    fortinet: [
        { key: "ssh_username", label: tr("SSH Username"), type: "text", required: true },
        { key: "ssh_password", label: tr("SSH Password"), type: "password", required: true },
        { key: "vdom", label: tr("VDOM (optional)"), type: "text" },
        { key: "ssh_port", label: tr("SSH Port"), type: "number", default: 22 },
    ],
    linux: [
        { key: "ssh_username", label: tr("SSH Username"), type: "text", required: true },
        { key: "ssh_password", label: tr("SSH Password"), type: "password", required: true },
        { key: "sudo_password", label: tr("Sudo Password (optional)"), type: "password" },
        { key: "ssh_port", label: tr("SSH Port"), type: "number", default: 22 },
    ],
    apache: [
        { key: "ssh_username", label: tr("SSH Username"), type: "text", required: true },
        { key: "ssh_password", label: tr("SSH Password"), type: "password", required: true },
        { key: "sudo_password", label: tr("Sudo Password (optional)"), type: "password" },
        { key: "ssh_port", label: tr("SSH Port"), type: "number", default: 22 },
    ],
    mongodb: [
        { key: "ssh_username", label: tr("SSH Username"), type: "text", required: true },
        { key: "ssh_password", label: tr("SSH Password"), type: "password", required: true },
        { key: "sudo_password", label: tr("Sudo Password (optional)"), type: "password" },
        { key: "mongo_username", label: tr("MongoDB Username (optional)"), type: "text" },
        { key: "mongo_password", label: tr("MongoDB Password (optional)"), type: "password" },
        { key: "ssh_port", label: tr("SSH Port"), type: "number", default: 22 },
    ],
    mssql: [
        { key: "mssql_username", label: tr("SQL Server Login"), type: "text", required: true },
        { key: "mssql_password", label: tr("SQL Server Password"), type: "password", required: true },
        { key: "mssql_port", label: tr("Port"), type: "number", default: 1433 },
    ],
    windows: [
        { key: "windows_username", label: tr("Windows Username"), type: "text", required: true },
        { key: "windows_password", label: tr("Windows Password"), type: "password", required: true },
        { key: "winrm_port", label: tr("WinRM Port"), type: "number", default: 5985 },
    ],
    active_directory: WINRM_FIELDS,
    dns_server: WINRM_FIELDS,
    dhcp_server: WINRM_FIELDS,
    iis: WINRM_FIELDS,
};

const TECH_LABELS = { active_directory: "Active Directory", dns_server: "Windows DNS Server", dhcp_server: "Windows DHCP Server", iis: "IIS 10" };

const RECURRENCE_LABELS = { once: tr("Once"), hourly: tr("Hourly"), daily: tr("Daily"), weekly: tr("Weekly") };

const emptyForm = {
    job_name: "",
    job_type: "discovery",
    recurrence: "daily",
    hour: 2,
    minute: 0,
    day_of_week: 0,
    target: "",
    scan_type: "well_known_ports",
    ports: "",
    protocol: "TCP",
    technology: "cisco",
    asset_id: "",
    audit_params: {},
};

const scheduleSummary = (job) => {
    const hh = String(job.hour ?? 0).padStart(2, "0");
    const mm = String(job.minute ?? 0).padStart(2, "0");
    if (job.recurrence === "hourly") return tr("Every hour at :{{mm}}", { mm });
    if (job.recurrence === "weekly") return tr("Weekly on {{value}} at {{hh}}:{{mm}}", { value: DAY_NAMES[job.day_of_week ?? 0], hh, mm });
    if (job.recurrence === "once") return tr("Once at {{hh}}:{{mm}}", { hh, mm });
    return tr("Daily at {{hh}}:{{mm}}", { hh, mm });
};

export const ScheduledJobsPage = ({ jobType }) => {
    const dispatch = useDispatch();
    const canReadDiscovery = usePermission("asset_auto_discovery", "read");
    const canReadAuditing = usePermission("auditing", "read");
    const canWriteDiscovery = usePermission("asset_auto_discovery", "write");
    const canWriteAuditing = usePermission("auditing", "write");

    const canRead = jobType === "discovery" ? canReadDiscovery : canReadAuditing;
    const canWrite = jobType === "discovery" ? canWriteDiscovery : canWriteAuditing;
    const pageTitle = jobType === "discovery" ? tr("Schedule Discovery") : tr("Schedule Auditing");

    const { jobs, runsByJobId, isLoading, isSaving, error, successMessage } = useSelector((state) => state.scheduling);
    const { assets } = useSelector((state) => state.assets);

    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState({ ...emptyForm, job_type: jobType });
    const [historyJobId, setHistoryJobId] = useState(null);

    useEffect(() => {
        if (canRead) {
            dispatch(fetchScheduledJobs());
            dispatch(fetchAssets());
        }
    }, [dispatch, canRead]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 5000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    if (!canRead) {
        return <AccessDenied menuName={pageTitle} />;
    }

    const visibleJobs = jobs.filter((j) => j.job_type === jobType);

    const handleCreate = () => {
        const payload = { ...form };
        if (form.job_type === "discovery") {
            payload.audit_params = undefined;
            payload.technology = undefined;
            payload.asset_id = undefined;
        } else {
            payload.target = undefined;
            payload.scan_type = undefined;
            payload.ports = undefined;
            payload.protocol = undefined;
            payload.asset_id = Number(form.asset_id) || undefined;
            const fields = TECH_FIELDS[form.technology] || [];
            const params = {};
            fields.forEach((f) => {
                const v = form.audit_params[f.key];
                if (v !== undefined && v !== "") params[f.key] = f.type === "number" ? Number(v) : v;
            });
            payload.audit_params = params;
        }
        if (payload.recurrence !== "weekly") payload.day_of_week = undefined;
        dispatch(createScheduledJob(payload));
        setShowCreate(false);
        setForm({ ...emptyForm, job_type: jobType });
    };

    const handleToggleEnabled = (job) => {
        dispatch(updateScheduledJob({ jobId: job.id, data: { enabled: !job.enabled } })).then(() => dispatch(fetchScheduledJobs()));
    };

    const handleDelete = (job) => {
        if (window.confirm(tr("Delete scheduled job \"{{job_name}}\"?", { job_name: job.job_name }))) {
            dispatch(deleteScheduledJob(job.id));
        }
    };

    const handleRunNow = (job) => {
        dispatch(runScheduledJobNow(job.id)).then(() => dispatch(fetchScheduledJobs()));
    };

    const handleViewHistory = (job) => {
        setHistoryJobId(job.id);
        dispatch(fetchJobRuns(job.id));
    };

    const auditTechFields = TECH_FIELDS[form.technology] || [];

    return (
        <div className="sched-container">
            <div className="sched-toolbar">
                <h2 className="sched-page-title">{pageTitle}</h2>
                <button className="sched-btn sched-btn-primary" onClick={() => setShowCreate(true)}>
                    <i className="fa-solid fa-plus" /> {" "}{tr("New Schedule")}
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`sched-toast ${error ? "sched-toast-error" : "sched-toast-success"}`}>{error || successMessage}</div>
            )}

            <div className="sched-table-container">
                {isLoading ? (
                    <div className="sched-empty">{tr("Loading scheduled jobs…")}</div>
                ) : visibleJobs.length === 0 ? (
                    <div className="sched-empty">
                        {jobType === "discovery"
                            ? tr("No scheduled discovery scans yet. Click \"New Schedule\" to automate one.")
                            : tr("No scheduled audits yet. Click \"New Schedule\" to automate one.")}
                    </div>
                ) : (
                    <table className="sched-table">
                        <thead>
                            <tr>
                                <th>{tr("Name")}</th>
                                <th>{tr("Type")}</th>
                                <th>{tr("Schedule")}</th>
                                <th>{tr("Next run")}</th>
                                <th>{tr("Last run")}</th>
                                <th>{tr("Enabled")}</th>
                                <th>{tr("Actions")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {visibleJobs.map((job) => (
                                <tr key={job.id}>
                                    <td className="sched-cell-strong">{job.job_name}</td>
                                    <td>
                                        {job.job_type === "discovery" ? tr("Discovery") : tr("Audit ({{technology}}{{value}})", { technology: job.technology, value: job.asset_name ? ` — ${job.asset_name}` : "" })}
                                    </td>
                                    <td>{scheduleSummary(job)}</td>
                                    <td>{new Date(job.next_run_at).toLocaleString(uiLocale())}</td>
                                    <td>
                                        {job.last_run_at ? (
                                            <span className={`sched-badge ${job.last_run_status === "success" ? "sched-badge-success" : "sched-badge-failed"}`}>
                                                {job.last_run_status}
                                            </span>
                                        ) : (
                                            tr("Never")
                                        )}
                                    </td>
                                    <td>
                                        <label className="sched-switch">
                                            <input type="checkbox" checked={job.enabled} onChange={() => handleToggleEnabled(job)} />
                                            <span className="sched-switch-slider" />
                                        </label>
                                    </td>
                                    <td>
                                        <div className="sched-row-actions">
                                            <button className="sched-link-btn" onClick={() => handleRunNow(job)}>{tr("Run now")}</button>
                                            <button className="sched-link-btn" onClick={() => handleViewHistory(job)}>{tr("History")}</button>
                                            <button className="sched-link-btn sched-link-btn-muted" onClick={() => handleDelete(job)}>{tr("Delete")}</button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {showCreate && (
                <div className="sched-modal-backdrop" onClick={() => setShowCreate(false)}>
                    <div className="sched-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>{jobType === "discovery" ? tr("New scheduled discovery scan") : tr("New scheduled audit")}</h3>

                        <div className="sched-field">
                            <label>{tr("Job name")}</label>
                            <input value={form.job_name} onChange={(e) => setForm({ ...form, job_name: e.target.value })} />
                        </div>

                        {form.job_type === "discovery" ? (
                            <>
                                <div className="sched-field">
                                    <label>{tr("Target (IP / CIDR / range)")}</label>
                                    <input placeholder="192.168.1.0/24" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
                                </div>
                                <div className="sched-field">
                                    <label>{tr("Scan type")}</label>
                                    <select value={form.scan_type} onChange={(e) => setForm({ ...form, scan_type: e.target.value })}>
                                        <option value="well_known_ports">{tr("Well-known ports")}</option>
                                        <option value="all_ports">{tr("All ports")}</option>
                                        <option value="custom_ports">{tr("Custom ports")}</option>
                                    </select>
                                </div>
                                {form.scan_type === "custom_ports" && (
                                    <div className="sched-field">
                                        <label>{tr("Ports")}</label>
                                        <input placeholder="80,443,8080" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} />
                                    </div>
                                )}
                            </>
                        ) : (
                            <>
                                <div className="sched-field">
                                    <label>{tr("Technology")}</label>
                                    <select
                                        value={form.technology}
                                        onChange={(e) => setForm({ ...form, technology: e.target.value, audit_params: {} })}
                                    >
                                        {Object.keys(TECH_FIELDS).map((t) => (
                                            <option key={t} value={t}>{TECH_LABELS[t] || t}</option>
                                        ))}
                                    </select>
                                </div>
                                <div className="sched-field">
                                    <label>{tr("Asset")}</label>
                                    <select value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })}>
                                        <option value="">{tr("— Select an asset —")}</option>
                                        {assets.map((a) => (
                                            <option key={a.id} value={a.id}>{a.asset_name}</option>
                                        ))}
                                    </select>
                                </div>
                                {auditTechFields.map((f) => (
                                    <div className="sched-field" key={f.key}>
                                        <label>{f.label}</label>
                                        <input
                                            type={f.type}
                                            placeholder={f.default !== undefined ? String(f.default) : ""}
                                            value={form.audit_params[f.key] ?? ""}
                                            onChange={(e) =>
                                                setForm({ ...form, audit_params: { ...form.audit_params, [f.key]: e.target.value } })
                                            }
                                        />
                                    </div>
                                ))}
                                <p className="sched-modal-hint">
                                    {tr("Credentials are stored encrypted at rest so this job can run unattended - the one exception to this app's usual \"never stored\" rule, same as NOC's SNMP credentials.")}
                                </p>
                            </>
                        )}

                        <div className="sched-field">
                            <label>{tr("Recurrence")}</label>
                            <select value={form.recurrence} onChange={(e) => setForm({ ...form, recurrence: e.target.value })}>
                                {Object.entries(RECURRENCE_LABELS).map(([k, v]) => (
                                    <option key={k} value={k}>{v}</option>
                                ))}
                            </select>
                        </div>
                        {form.recurrence !== "hourly" && (
                            <div className="sched-field">
                                <label>{tr("Time of day (hour)")}</label>
                                <input type="number" min={0} max={23} value={form.hour} onChange={(e) => setForm({ ...form, hour: Number(e.target.value) })} />
                            </div>
                        )}
                        <div className="sched-field">
                            <label>{tr("Minute")}</label>
                            <input type="number" min={0} max={59} value={form.minute} onChange={(e) => setForm({ ...form, minute: Number(e.target.value) })} />
                        </div>
                        {form.recurrence === "weekly" && (
                            <div className="sched-field">
                                <label>{tr("Day of week")}</label>
                                <select value={form.day_of_week} onChange={(e) => setForm({ ...form, day_of_week: Number(e.target.value) })}>
                                    {DAY_NAMES.map((d, i) => (
                                        <option key={d} value={i}>{d}</option>
                                    ))}
                                </select>
                            </div>
                        )}

                        <div className="sched-modal-actions">
                            <button className="sched-btn" onClick={() => setShowCreate(false)}>{tr("Cancel")}</button>
                            <button
                                className="sched-btn sched-btn-primary"
                                onClick={handleCreate}
                                disabled={
                                    isSaving ||
                                    !canWrite ||
                                    !form.job_name ||
                                    (form.job_type === "discovery" ? !form.target : !form.asset_id)
                                }
                            >
                                {tr("Create")}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {historyJobId !== null && (
                <div className="sched-modal-backdrop" onClick={() => setHistoryJobId(null)}>
                    <div className="sched-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>{tr("Run history")}</h3>
                        {(runsByJobId[historyJobId] || []).length === 0 ? (
                            <div className="sched-empty">{tr("No runs yet.")}</div>
                        ) : (
                            <table className="sched-table">
                                <thead>
                                    <tr>
                                        <th>{tr("Started")}</th>
                                        <th>{tr("Status")}</th>
                                        <th>{tr("Message")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {(runsByJobId[historyJobId] || []).map((r) => (
                                        <tr key={r.id}>
                                            <td>{r.started_at ? new Date(r.started_at).toLocaleString(uiLocale()) : "—"}</td>
                                            <td>
                                                <span className={`sched-badge ${r.status === "success" ? "sched-badge-success" : "sched-badge-failed"}`}>
                                                    {r.status}
                                                </span>
                                            </td>
                                            <td>{r.message || "—"}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                        <div className="sched-modal-actions">
                            <button className="sched-btn" onClick={() => setHistoryJobId(null)}>{tr("Close")}</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ScheduledJobsPage;
