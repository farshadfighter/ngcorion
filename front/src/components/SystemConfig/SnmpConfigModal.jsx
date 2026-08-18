import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchSection, saveSection } from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";
import { SecretField } from "./SecretField";

const SECTION = "snmp";

/** Mirrors SnmpAuthProtocolEnum / SnmpPrivProtocolEnum in app/models/enums.py.
 *  The values are case-sensitive on the wire. */
const AUTH_PROTOCOLS = ["MD5", "SHA"];
const PRIV_PROTOCOLS = ["DES", "AES"];

const SnmpForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings } = useSelector(
        (state) => state.systemConfig
    );
    const config = stored?.config;

    const [version, setVersion] = useState(config?.version || "v2c");
    const [v2Community, setV2Community] = useState(config?.v2_community || "");
    const [v2Port, setV2Port] = useState(config?.v2_port ?? 161);
    const [v3Username, setV3Username] = useState(config?.v3_username || "");
    const [authProtocol, setAuthProtocol] = useState(
        config?.v3_auth_protocol || "SHA"
    );
    const [authPassword, setAuthPassword] = useState(
        config?.v3_auth_password || ""
    );
    const [privProtocol, setPrivProtocol] = useState(
        config?.v3_priv_protocol || "AES"
    );
    const [privPassword, setPrivPassword] = useState(
        config?.v3_priv_password || ""
    );
    const [v3Port, setV3Port] = useState(config?.v3_port ?? 161);
    const [localError, setLocalError] = useState(null);

    const isV3 = version === "v3";

    const handleSave = async () => {
        setLocalError(null);

        const port = Number(isV3 ? v3Port : v2Port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            setLocalError("Port must be between 1 and 65535.");
            return;
        }

        const payload = { version };
        if (isV3) {
            const missing = [];
            if (!v3Username.trim()) missing.push("username");
            if (!authPassword) missing.push("auth password");
            if (!privPassword) missing.push("privacy password");
            if (missing.length) {
                setLocalError(`Required for SNMP v3: ${missing.join(", ")}.`);
                return;
            }
            payload.v3_username = v3Username.trim();
            payload.v3_auth_protocol = authProtocol;
            payload.v3_auth_password = authPassword;
            payload.v3_priv_protocol = privProtocol;
            payload.v3_priv_password = privPassword;
            payload.v3_port = port;
        } else {
            if (!v2Community.trim()) {
                setLocalError("Community string is required for SNMP v2c.");
                return;
            }
            payload.v2_community = v2Community.trim();
            payload.v2_port = port;
        }

        const res = await dispatch(saveSection({ section: SECTION, payload }));
        if (saveSection.fulfilled.match(res) && !res.payload?.data?.warning) {
            onClose();
        }
    };

    return (
        <ConfigModal
            title="SNMP Configurations"
            onClose={onClose}
            onSave={handleSave}
            isSaving={!!saving[SECTION]}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
        >
            <div className="sc-tabs">
                <button
                    type="button"
                    className={`sc-tab${!isV3 ? " is-active" : ""}`}
                    onClick={() => setVersion("v2c")}
                >
                    SNMP v2c
                </button>
                <button
                    type="button"
                    className={`sc-tab${isV3 ? " is-active" : ""}`}
                    onClick={() => setVersion("v3")}
                >
                    SNMP v3
                </button>
            </div>

            {isV3 ? (
                <>
                    <label className="sc-field">
                        <span>Username</span>
                        <input
                            type="text"
                            value={v3Username}
                            onChange={(e) => setV3Username(e.target.value)}
                            maxLength={255}
                        />
                    </label>

                    <div className="sc-row">
                        <label className="sc-field">
                            <span>Auth Protocol</span>
                            <select
                                value={authProtocol}
                                onChange={(e) => setAuthProtocol(e.target.value)}
                            >
                                {AUTH_PROTOCOLS.map((p) => (
                                    <option key={p} value={p}>
                                        {p}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <SecretField
                            label="Auth Password"
                            value={authPassword}
                            onChange={setAuthPassword}
                        />
                    </div>

                    <div className="sc-row">
                        <label className="sc-field">
                            <span>Privacy Protocol</span>
                            <select
                                value={privProtocol}
                                onChange={(e) => setPrivProtocol(e.target.value)}
                            >
                                {PRIV_PROTOCOLS.map((p) => (
                                    <option key={p} value={p}>
                                        {p}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <SecretField
                            label="Privacy Password"
                            value={privPassword}
                            onChange={setPrivPassword}
                        />
                    </div>

                    <label className="sc-field">
                        <span>Port</span>
                        <input
                            type="number"
                            min={1}
                            max={65535}
                            value={v3Port}
                            onChange={(e) => setV3Port(e.target.value)}
                        />
                    </label>
                </>
            ) : (
                <>
                    <label className="sc-field">
                        <span>Community String</span>
                        <input
                            type="text"
                            value={v2Community}
                            onChange={(e) => setV2Community(e.target.value)}
                            placeholder="public"
                            maxLength={255}
                        />
                    </label>
                    <label className="sc-field">
                        <span>Port</span>
                        <input
                            type="number"
                            min={1}
                            max={65535}
                            value={v2Port}
                            onChange={(e) => setV2Port(e.target.value)}
                        />
                    </label>
                </>
            )}
        </ConfigModal>
    );
};

/**
 * SNMP Configurations dialog.
 *
 * v2c and v3 need disjoint field sets and the backend validates them
 * separately, so the version acts as a mode switch rather than just another
 * field: only the selected version's values are sent.
 */
export const SnmpConfigModal = ({ onClose }) => {
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
                title="SNMP Configurations"
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <SnmpForm stored={stored} onClose={onClose} />;
};

export default SnmpConfigModal;
