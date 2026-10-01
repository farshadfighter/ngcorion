import React from "react";
import { orDash, titleCase, formatDate } from "../riskConstants";
import { t } from "../../../i18n";

const COLUMNS = [
    t("Port"),
    t("Protocol"),
    t("Service"),
    t("Severity"),
    t("Severity Score"),
    t("Status"),
    t("Approved"),
    t("Included in Risk"),
    t("First Seen"),
    t("Last Seen"),
    t("Action"),
];

/** Open ports observed on the asset — fully covered by the risk detail payload. */
export const OpenPortsTable = ({ ports }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">{t("Open Ports")}</h3>
        <div className="ard-table-wrapper">
            <table className="ard-table">
                <thead>
                    <tr>
                        {COLUMNS.map((label) => (
                            <th key={label}>{label}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {ports.length === 0 && (
                        <tr>
                            <td colSpan={COLUMNS.length} className="ard-table-empty">
                                {t("No open ports recorded for this asset.")}
                            </td>
                        </tr>
                    )}
                    {ports.map((port) => (
                        <tr key={port.id}>
                            <td>{orDash(port.port)}</td>
                            <td>{port.protocol ? port.protocol.toUpperCase() : "-"}</td>
                            <td>{orDash(port.service_name)}</td>
                            <td>{port.severity ? titleCase(port.severity) : "-"}</td>
                            <td>{orDash(port.severity_score)}</td>
                            <td>{port.status ? titleCase(port.status) : "-"}</td>
                            <td>{port.is_approved ? t("Yes") : t("No")}</td>
                            <td>{port.is_included_in_risk ? t("Yes") : t("No")}</td>
                            <td>{formatDate(port.first_seen_at)}</td>
                            <td>{formatDate(port.last_seen_at)}</td>
                            <td>
                                <button
                                    type="button"
                                    className="ard-icon-btn"
                                    disabled
                                    title={t("Edit (not wired up yet)")}
                                    aria-label={t("Edit port {{port}}", { port: port.port })}
                                >
                                    <i className="fa-solid fa-pen" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

export default OpenPortsTable;
