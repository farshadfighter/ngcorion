import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import {
    fetchSection,
    saveSection,
    testSection,
    clearTestResult,
} from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";
import { SecretField } from "./SecretField";

const SECTION = "smtp";

/** Transport modes. use_tls and use_ssl are mutually exclusive server-side, so
 *  they are one choice here rather than two independent checkboxes. */
const TRANSPORTS = [
    { key: "starttls", label: "STARTTLS", port: 587, use_tls: true, use_ssl: false },
    { key: "ssl", label: "SSL/TLS", port: 465, use_tls: false, use_ssl: true },
    { key: "none", label: "None", port: 25, use_tls: false, use_ssl: false },
];

const transportOf = (config) => {
    if (config?.use_ssl) return "ssl";
    if (config?.use_tls) return "starttls";
    return config ? "none" : "starttls";
};

const SmtpForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings, testing, testResults } = useSelector(
        (state) => state.systemConfig
    );
    const config = stored?.config;

    const [host, setHost] = useState(config?.host || "");
    const [port, setPort] = useState(config?.port ?? 587);
    const [username, setUsername] = useState(config?.username || "");
    const [password, setPassword] = useState(config?.password || "");
    const [transport, setTransport] = useState(transportOf(config));
    const [fromEmail, setFromEmail] = useState(config?.from_email || "");
    const [fromName, setFromName] = useState(config?.from_name || "");
    const [testTo, setTestTo] = useState("");
    const [localError, setLocalError] = useState(null);

    const testResult = testResults[SECTION];
    // The test runs against the stored settings, so it only makes sense once
    // something has been saved.
    const hasStoredConfig = !!config;

    const handleTransportChange = (key) => {
        setTransport(key);
        const preset = TRANSPORTS.find((t) => t.key === key);
        // Only nudge the port when it is still a default of another mode, so a
        // deliberately custom port survives the switch.
        if (preset && TRANSPORTS.some((t) => Number(port) === t.port)) {
            setPort(preset.port);
        }
    };

    const buildPayload = () => {
        const preset = TRANSPORTS.find((t) => t.key === transport);
        return {
            host: host.trim(),
            port: Number(port),
            username: username.trim(),
            password,
            use_tls: preset.use_tls,
            use_ssl: preset.use_ssl,
            from_email: fromEmail.trim(),
            from_name: fromName.trim() || null,
        };
    };

    const validate = () => {
        if (!host.trim()) return "Enter the SMTP server host.";
        const portNumber = Number(port);
        if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
            return "Port must be between 1 and 65535.";
        }
        if (!fromEmail.trim()) return "Enter the sender email address.";
        // The backend validates with EmailStr; catch the obvious case here.
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fromEmail.trim())) {
            return "Sender email address is not valid.";
        }
        return null;
    };

    const handleSave = async () => {
        const problem = validate();
        setLocalError(problem);
        if (problem) return;

        const res = await dispatch(
            saveSection({ section: SECTION, payload: buildPayload() })
        );
        if (saveSection.fulfilled.match(res) && !res.payload?.data?.warning) {
            onClose();
        }
    };

    const handleTest = async () => {
        setLocalError(null);
        dispatch(clearTestResult(SECTION));

        if (!testTo.trim()) {
            setLocalError("Enter an address to send the test to.");
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(testTo.trim())) {
            setLocalError("Test recipient address is not valid.");
            return;
        }

        dispatch(
            testSection({ section: SECTION, payload: { to: testTo.trim() } })
        );
    };

    return (
        <ConfigModal
            title="SMTP Configurations"
            onClose={onClose}
            onSave={handleSave}
            isSaving={!!saving[SECTION]}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
        >
            <label className="sc-field">
                <span>SMTP Host</span>
                <input
                    type="text"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="smtp.example.com"
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
                    <span>Encryption</span>
                    <select
                        value={transport}
                        onChange={(e) => handleTransportChange(e.target.value)}
                    >
                        {TRANSPORTS.map((t) => (
                            <option key={t.key} value={t.key}>
                                {t.label}
                            </option>
                        ))}
                    </select>
                </label>
            </div>

            <div className="sc-row">
                <label className="sc-field">
                    <span>Username</span>
                    <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        maxLength={255}
                        autoComplete="off"
                    />
                </label>
                <SecretField
                    label="Password"
                    value={password}
                    onChange={setPassword}
                />
            </div>

            <div className="sc-row">
                <label className="sc-field">
                    <span>From Email</span>
                    <input
                        type="email"
                        value={fromEmail}
                        onChange={(e) => setFromEmail(e.target.value)}
                        placeholder="ngcorion@example.com"
                    />
                </label>
                <label className="sc-field">
                    <span>
                        From Name <em>(optional)</em>
                    </span>
                    <input
                        type="text"
                        value={fromName}
                        onChange={(e) => setFromName(e.target.value)}
                        maxLength={255}
                    />
                </label>
            </div>

            <div className="sc-test">
                <p className="sc-test-title">Send a test email</p>
                <p className="sc-test-note">
                    The test uses the <strong>saved</strong> settings — save
                    first if you have just changed anything.
                </p>
                <div className="sc-test-row">
                    <input
                        type="email"
                        value={testTo}
                        onChange={(e) => setTestTo(e.target.value)}
                        placeholder="you@example.com"
                        disabled={!hasStoredConfig}
                    />
                    <button
                        type="button"
                        className="sc-btn sc-btn-ghost"
                        onClick={handleTest}
                        disabled={!hasStoredConfig || !!testing[SECTION]}
                    >
                        {testing[SECTION] ? (
                            <>
                                <i className="fa-solid fa-spinner fa-spin" /> Sending…
                            </>
                        ) : (
                            "Send test"
                        )}
                    </button>
                </div>
                {!hasStoredConfig && (
                    <p className="sc-test-note">
                        Save the settings before sending a test.
                    </p>
                )}
                {testResult && (
                    <p
                        className={
                            testResult.success ? "sc-test-ok" : "sc-test-fail"
                        }
                    >
                        <i
                            className={`fa-solid ${
                                testResult.success
                                    ? "fa-circle-check"
                                    : "fa-circle-exclamation"
                            }`}
                        />{" "}
                        {testResult.message}
                    </p>
                )}
            </div>
        </ConfigModal>
    );
};

/**
 * SMTP Configurations dialog.
 *
 * Unlike the other sections this one changes nothing on the host — it only
 * stores settings, so its PUT never returns a warning. The test button posts to
 * /smtp/test, which sends a real message using the stored configuration.
 */
export const SmtpConfigModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { sections, loading, errors } = useSelector(
        (state) => state.systemConfig
    );
    const stored = sections[SECTION];

    useEffect(() => {
        dispatch(fetchSection(SECTION));
        return () => dispatch(clearTestResult(SECTION));
    }, [dispatch]);

    if (!stored) {
        return (
            <ConfigModal
                title="SMTP Configurations"
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <SmtpForm stored={stored} onClose={onClose} />;
};

export default SmtpConfigModal;
