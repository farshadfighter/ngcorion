import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchSection, saveSection } from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";

const SECTION = "syslog";

/** Mirrors SyslogProtocolEnum in app/models/enums.py — case-sensitive. */
const PROTOCOLS = ["UDP", "TCP"];

/** The standard syslog facilities. The backend accepts any single token and
 *  currently records the choice as a comment in the rsyslog drop-in, so this
 *  list is for convenience rather than a backend constraint. */
const FACILITIES = [
    "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
    "auth", "authpriv", "cron", "daemon", "kern",
    "mail", "syslog", "user",
];

const SyslogForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings } = useSelector(
        (state) => state.systemConfig
    );
    const config = stored?.config;

    const [serverIp, setServerIp] = useState(config?.server_ip || "");
    const [port, setPort] = useState(config?.port ?? 514);
    const [protocol, setProtocol] = useState(config?.protocol || "UDP");
    const [facility, setFacility] = useState(config?.facility || "local0");
    const [localError, setLocalError] = useState(null);

    const handleSave = async () => {
        setLocalError(null);

        const host = serverIp.trim();
        if (!host) {
            setLocalError("Enter the syslog server address.");
            return;
        }
        // The backend rejects any whitespace inside the value, so catch it here
        // rather than round-tripping for a 422.
        if (/\s/.test(host)) {
            setLocalError("Server address must not contain spaces.");
            return;
        }

        const portNumber = Number(port);
        if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
            setLocalError("Port must be between 1 and 65535.");
            return;
        }

        const payload = {
            server_ip: host,
            port: portNumber,
            protocol,
            facility,
        };

        const res = await dispatch(saveSection({ section: SECTION, payload }));
        if (saveSection.fulfilled.match(res) && !res.payload?.data?.warning) {
            onClose();
        }
    };

    return (
        <ConfigModal
            title="Syslog Configurations"
            onClose={onClose}
            onSave={handleSave}
            isSaving={!!saving[SECTION]}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
        >
            <label className="sc-field">
                <span>Server IP Address</span>
                <input
                    type="text"
                    value={serverIp}
                    onChange={(e) => setServerIp(e.target.value)}
                    placeholder="10.0.0.50"
                    maxLength={255}
                />
            </label>

            <div className="sc-row">
                <label className="sc-field">
                    <span>Port</span>
                    <input
                        type="number"
                        min={1}
                        max={65535}
                        value={port}
                        onChange={(e) => setPort(e.target.value)}
                    />
                </label>
                <label className="sc-field">
                    <span>Protocol</span>
                    <select
                        value={protocol}
                        onChange={(e) => setProtocol(e.target.value)}
                    >
                        {PROTOCOLS.map((p) => (
                            <option key={p} value={p}>
                                {p}
                            </option>
                        ))}
                    </select>
                </label>
            </div>

            <label className="sc-field">
                <span>Facility</span>
                <select
                    value={facility}
                    onChange={(e) => setFacility(e.target.value)}
                >
                    {FACILITIES.map((f) => (
                        <option key={f} value={f}>
                            {f}
                        </option>
                    ))}
                </select>
            </label>
        </ConfigModal>
    );
};

/**
 * Syslog Configurations dialog: where the appliance forwards its logs.
 *
 * Saving rewrites the rsyslog drop-in and restarts rsyslog, so a failure to
 * apply comes back as `warning` even though the settings were stored.
 */
export const SyslogConfigModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { sections, loading, errors } = useSelector(
        (state) => state.systemConfig
    );
    const stored = sections[SECTION];

    useEffect(() => {
        dispatch(fetchSection(SECTION));
    }, [dispatch]);

    if (!stored) {
        return (
            <ConfigModal
                title="Syslog Configurations"
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <SyslogForm stored={stored} onClose={onClose} />;
};

export default SyslogConfigModal;
