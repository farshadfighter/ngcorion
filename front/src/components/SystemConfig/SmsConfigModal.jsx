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

const SECTION = "sms";

/**
 * Providers the backend builds a documented request for (service._sms_request).
 * Anything else falls through to a generic JSON POST at server_address, so the
 * list is a convenience, not a restriction — hence the "Other" entry.
 * Matching is case-insensitive on the backend.
 */
const KNOWN_PROVIDERS = [
    { value: "kavenegar", label: "Kavenegar", base: "https://api.kavenegar.com" },
    { value: "ghasedak", label: "Ghasedak", base: "https://api.ghasedak.me" },
];

const OTHER = "__other__";

const SmsForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings, testing, testResults } = useSelector(
        (state) => state.systemConfig
    );
    const config = stored?.config;

    const storedProvider = (config?.provider || "").toLowerCase();
    const isKnown = KNOWN_PROVIDERS.some((p) => p.value === storedProvider);

    const [providerChoice, setProviderChoice] = useState(
        config ? (isKnown ? storedProvider : OTHER) : "kavenegar"
    );
    const [customProvider, setCustomProvider] = useState(
        isKnown ? "" : config?.provider || ""
    );
    const [serverAddress, setServerAddress] = useState(
        config?.server_address || KNOWN_PROVIDERS[0].base
    );
    const [apiKey, setApiKey] = useState(config?.api_key || "");
    const [senderNumber, setSenderNumber] = useState(config?.sender_number || "");
    const [username, setUsername] = useState(config?.username || "");
    const [password, setPassword] = useState(config?.password || "");
    const [testPhone, setTestPhone] = useState("");
    const [localError, setLocalError] = useState(null);

    const isOther = providerChoice === OTHER;
    const testResult = testResults[SECTION];
    const hasStoredConfig = !!config;

    const handleProviderChange = (value) => {
        setProviderChoice(value);
        const preset = KNOWN_PROVIDERS.find((p) => p.value === value);
        // Fill in the provider's documented base URL, but never overwrite an
        // address the user has already customised.
        if (
            preset &&
            (!serverAddress ||
                KNOWN_PROVIDERS.some((p) => p.base === serverAddress))
        ) {
            setServerAddress(preset.base);
        }
    };

    const resolvedProvider = isOther
        ? customProvider.trim()
        : providerChoice;

    const validate = () => {
        if (!resolvedProvider) return "Enter the provider name.";
        if (!serverAddress.trim()) return "Enter the provider server address.";
        if (!apiKey) return "Enter the API key.";
        return null;
    };

    const handleSave = async () => {
        const problem = validate();
        setLocalError(problem);
        if (problem) return;

        const payload = {
            provider: resolvedProvider,
            server_address: serverAddress.trim(),
            api_key: apiKey,
            sender_number: senderNumber.trim() || null,
            username: username.trim() || null,
            password: password || null,
        };

        const res = await dispatch(saveSection({ section: SECTION, payload }));
        if (saveSection.fulfilled.match(res) && !res.payload?.data?.warning) {
            onClose();
        }
    };

    const handleTest = () => {
        setLocalError(null);
        dispatch(clearTestResult(SECTION));

        const phone = testPhone.trim();
        if (!phone) {
            setLocalError("Enter a phone number to send the test to.");
            return;
        }
        // The backend accepts digits with an optional leading +.
        if (!/^\+?\d{3,}$/.test(phone)) {
            setLocalError("Phone number must be digits, optionally starting +.");
            return;
        }

        dispatch(testSection({ section: SECTION, payload: { phone } }));
    };

    return (
        <ConfigModal
            title="SMS Configurations"
            onClose={onClose}
            onSave={handleSave}
            isSaving={!!saving[SECTION]}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
        >
            <div className="sc-row">
                <label className="sc-field">
                    <span>Provider</span>
                    <select
                        value={providerChoice}
                        onChange={(e) => handleProviderChange(e.target.value)}
                    >
                        {KNOWN_PROVIDERS.map((p) => (
                            <option key={p.value} value={p.value}>
                                {p.label}
                            </option>
                        ))}
                        <option value={OTHER}>Other…</option>
                    </select>
                </label>
                {isOther ? (
                    <label className="sc-field">
                        <span>Provider Name</span>
                        <input
                            type="text"
                            value={customProvider}
                            onChange={(e) => setCustomProvider(e.target.value)}
                            placeholder="my-gateway"
                            maxLength={100}
                        />
                    </label>
                ) : (
                    <label className="sc-field">
                        <span>
                            Sender Number <em>(optional)</em>
                        </span>
                        <input
                            type="text"
                            value={senderNumber}
                            onChange={(e) => setSenderNumber(e.target.value)}
                            placeholder="10008663"
                            maxLength={50}
                        />
                    </label>
                )}
            </div>

            <label className="sc-field">
                <span>Server Address</span>
                <input
                    type="text"
                    value={serverAddress}
                    onChange={(e) => setServerAddress(e.target.value)}
                    placeholder="https://api.example.com"
                    maxLength={500}
                />
            </label>

            <SecretField label="API Key" value={apiKey} onChange={setApiKey} maxLength={500} />

            {isOther && (
                <>
                    <label className="sc-field">
                        <span>
                            Sender Number <em>(optional)</em>
                        </span>
                        <input
                            type="text"
                            value={senderNumber}
                            onChange={(e) => setSenderNumber(e.target.value)}
                            maxLength={50}
                        />
                    </label>
                    {/* Basic-auth credentials are only used by the generic
                        provider path, so they stay out of the way otherwise. */}
                    <div className="sc-row">
                        <label className="sc-field">
                            <span>
                                Username <em>(optional)</em>
                            </span>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                maxLength={255}
                                autoComplete="off"
                            />
                        </label>
                        <SecretField
                            label="Password (optional)"
                            value={password}
                            onChange={setPassword}
                        />
                    </div>
                </>
            )}

            <div className="sc-test">
                <p className="sc-test-title">Send a test SMS</p>
                <p className="sc-test-note">
                    The test uses the <strong>saved</strong> settings — save
                    first if you have just changed anything.
                </p>
                <div className="sc-test-row">
                    <input
                        type="tel"
                        value={testPhone}
                        onChange={(e) => setTestPhone(e.target.value)}
                        placeholder="09121234567"
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
 * SMS Configurations dialog.
 *
 * Kavenegar and Ghasedak have dedicated request shapes in the backend; any
 * other provider name falls back to a generic JSON POST, which is the only mode
 * that uses the basic-auth username/password — so those two fields appear only
 * for "Other".
 */
export const SmsConfigModal = ({ onClose }) => {
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
                title="SMS Configurations"
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <SmsForm stored={stored} onClose={onClose} />;
};

export default SmsConfigModal;
