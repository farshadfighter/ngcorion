import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { formatBytes, formatDate, formatWhen, num } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";

const CHECK_LABEL = {
    signature: "Signature",
    integrity: "File intact",
    format: "Package format",
    freshness: "Fits this database",
};

const STATUS_ICON = {
    ok: { name: "check", color: "#166534" },
    warn: { name: "warn", color: "#b45309" },
    fail: { name: "x", color: "#b91c1c" },
};

/** Uploads `file`, shows the server's checks and what the package holds, and
 *  starts the import once confirmed. Nothing is imported before that. */
export function CvePackageImport({ file, onStarted, onClose }) {
    const [sent, setSent] = useState(0);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [starting, setStarting] = useState(false);

    useEffect(() => {
        let alive = true;
        api.post("/api/cve/db/packages", file, {
            params: { file_name: file.name },
            headers: { "Content-Type": "application/octet-stream" },
            timeout: 0,
            onUploadProgress: (e) => alive && e.total && setSent(e.loaded / e.total),
        }).then(({ data }) => alive && setResult(data))
          .catch((err) => alive && setError(err.response?.data?.detail || "The package could not be uploaded"));
        return () => { alive = false; };
    }, [file]);

    const start = async () => {
        setStarting(true);
        try {
            const { data } = await api.post(`/api/cve/db/packages/${result.token}/import`);
            onStarted(data);
        } catch (err) {
            setError(err.response?.data?.detail || "The import could not be started");
            setStarting(false);
        }
    };

    const m = result?.manifest;
    const checking = !result && !error;

    return (
        <div className="cvx-overlay" role="dialog" aria-modal="true" aria-labelledby="cvx-import-title">
            <section className="cvx-modal cvx-modal-wide">
                <header className="cvx-modal-head">
                    <h2 id="cvx-import-title">Import update package</h2>
                    <p className="cvx-mono">{file.name} · {formatBytes(file.size)}</p>
                </header>

                <div className="cvx-modal-body">
                    {checking && (
                        <div className="cvx-uploading">
                            <span>{sent < 1 ? `Uploading… ${Math.round(sent * 100)}%` : "Checking the package…"}</span>
                            <div className="cvx-bar"><span style={{ width: `${Math.max(3, Math.round(sent * 100))}%` }} /></div>
                        </div>
                    )}
                    {error && <div className="cvx-note cvx-note-error">{error}</div>}

                    {result && (
                        <div className="cvx-import-grid">
                            <div>
                                <h3 className="cvx-h3">Checks</h3>
                                <ul className="cvx-checks">
                                    {result.checks.map((c) => {
                                        const s = STATUS_ICON[c.status] || STATUS_ICON.fail;
                                        return (
                                            <li key={c.name}>
                                                <Icon name={s.name} size={20} stroke={s.color} width={2.4} />
                                                <div>
                                                    <h4>{CHECK_LABEL[c.name] || c.name}</h4>
                                                    <p>{c.detail}</p>
                                                </div>
                                            </li>
                                        );
                                    })}
                                </ul>
                            </div>
                            {m && (
                                <aside className="cvx-summary-box">
                                    <h3 className="cvx-h3">What it holds</h3>
                                    <div className="cvx-kv"><span>Contents</span><b>{m.kind === "full" ? "The whole database" : `Changes since ${formatDate(m.since)}`}</b></div>
                                    <div className="cvx-kv"><span>Up to date as of</span><b>{formatWhen(m.until)}</b></div>
                                    <div className="cvx-kv"><span>CVE records</span><b>{num(m.counts?.cves)}</b></div>
                                    <div className="cvx-kv"><span>Known exploited</span><b>{num(m.counts?.kev)}</b></div>
                                    <div className="cvx-kv"><span>EPSS scores</span><b>{m.epss_date ? `${num(m.counts?.epss)} · ${formatDate(m.epss_date)}` : "—"}</b></div>
                                    <div className="cvx-kv"><span>Exported from</span><b>{m.instance || "—"}</b></div>
                                    <div className="cvx-kv"><span>Created</span><b>{formatWhen(m.created_at)}</b></div>
                                </aside>
                            )}
                        </div>
                    )}
                    {result && !result.importable && (
                        <div className="cvx-note cvx-note-error">This package cannot be imported. Nothing was changed.</div>
                    )}
                </div>

                <footer className="cvx-modal-foot">
                    <button type="button" className="cvx-btn" onClick={onClose}>Cancel</button>
                    <div className="cvx-foot-right">
                        <span className="cvx-muted cvx-small">Admin only · recorded in the audit log</span>
                        <button type="button" className="cvx-btn cvx-btn-primary" onClick={start}
                                disabled={!result?.importable || starting}>
                            <Icon name="upload" size={16} /> {starting ? "Starting…" : "Import"}
                        </button>
                    </div>
                </footer>
            </section>
        </div>
    );
}
