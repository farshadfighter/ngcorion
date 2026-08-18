import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchSection, saveSection } from "../../store/systemConfigSlice";
import { ConfigModal } from "./ConfigModal";
import { TIMEZONES } from "./timezones";

const SECTION = "time";

/** <input type="datetime-local"> wants "YYYY-MM-DDTHH:mm", not a full ISO string. */
const toLocalInput = (value) => {
    const d = value ? new Date(value) : new Date();
    if (Number.isNaN(d.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return (
        `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
        `T${pad(d.getHours())}:${pad(d.getMinutes())}`
    );
};

/**
 * The form itself. Split from the dialog below so it mounts only once the
 * stored config has arrived: initial state comes from props at mount, which
 * avoids seeding state from an effect.
 */
const TimeForm = ({ stored, onClose }) => {
    const dispatch = useDispatch();
    const { saving, errors, warnings } = useSelector(
        (state) => state.systemConfig
    );
    const config = stored?.config;

    const [mode, setMode] = useState(
        config && config.use_ntp === false ? "manual" : "timezone"
    );
    const [timezone, setTimezone] = useState(
        config?.timezone || stored?.server_time?.system_timezone || ""
    );
    const [useNtp, setUseNtp] = useState(config?.use_ntp ?? true);
    const [ntpServer, setNtpServer] = useState(config?.ntp_server || "");
    const [manualTime, setManualTime] = useState(
        toLocalInput(config?.manual_time || stored?.server_time?.current_time)
    );
    const [localError, setLocalError] = useState(null);

    const handleSave = async () => {
        setLocalError(null);

        if (!timezone) {
            setLocalError("Select a timezone.");
            return;
        }

        const payload = { timezone };
        if (mode === "manual") {
            if (!manualTime) {
                setLocalError("Pick a date and time.");
                return;
            }
            payload.use_ntp = false;
            payload.manual_time = new Date(manualTime).toISOString();
        } else {
            payload.use_ntp = useNtp;
            if (useNtp) {
                if (!ntpServer.trim()) {
                    setLocalError("Enter an NTP server address.");
                    return;
                }
                payload.ntp_server = ntpServer.trim();
            } else {
                // The backend requires manual_time whenever use_ntp is false.
                payload.manual_time = new Date(
                    manualTime || Date.now()
                ).toISOString();
            }
        }

        const res = await dispatch(saveSection({ section: SECTION, payload }));
        // Stay open when the host-level apply reported a warning, so it is read.
        if (saveSection.fulfilled.match(res) && !res.payload?.data?.warning) {
            onClose();
        }
    };

    const serverTime = stored?.server_time;

    return (
        <ConfigModal
            title="Time Configurations"
            onClose={onClose}
            onSave={handleSave}
            isSaving={!!saving[SECTION]}
            error={localError || errors[SECTION]}
            warning={warnings[SECTION]}
        >
            {serverTime?.current_time && (
                <p className="sc-hint">
                    Server clock:{" "}
                    <strong>
                        {new Date(serverTime.current_time).toLocaleString()}
                    </strong>
                    {serverTime.system_timezone
                        ? ` (${serverTime.system_timezone})`
                        : ""}
                    {serverTime.ntp_synchronized ? " · NTP synced" : ""}
                </p>
            )}

            <div className="sc-tabs">
                <button
                    type="button"
                    className={`sc-tab${mode === "timezone" ? " is-active" : ""}`}
                    onClick={() => setMode("timezone")}
                >
                    time zone
                </button>
                <button
                    type="button"
                    className={`sc-tab${mode === "manual" ? " is-active" : ""}`}
                    onClick={() => setMode("manual")}
                >
                    Manual Time
                </button>
            </div>

            <label className="sc-field">
                <span>time zone</span>
                <select
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                >
                    <option value="">select</option>
                    {TIMEZONES.map((tz) => (
                        <option key={tz} value={tz}>
                            {tz}
                        </option>
                    ))}
                </select>
            </label>

            {mode === "timezone" ? (
                <div className="sc-inline-field">
                    <label className="sc-checkbox">
                        <input
                            type="checkbox"
                            checked={useNtp}
                            onChange={(e) => setUseNtp(e.target.checked)}
                        />
                        <span>NTP</span>
                    </label>
                    <label className="sc-field sc-field-grow">
                        <span>NTP IP Address</span>
                        <input
                            type="text"
                            value={ntpServer}
                            onChange={(e) => setNtpServer(e.target.value)}
                            disabled={!useNtp}
                            placeholder="pool.ntp.org"
                            maxLength={255}
                        />
                    </label>
                </div>
            ) : (
                <label className="sc-field">
                    <span>Date and time</span>
                    <input
                        type="datetime-local"
                        value={manualTime}
                        onChange={(e) => setManualTime(e.target.value)}
                    />
                </label>
            )}
        </ConfigModal>
    );
};

/**
 * Time Configurations dialog.
 *
 * The Figma shows two tabs, "time zone" and "Manual Time". They are two modes
 * of one payload rather than two forms: the backend requires manual_time
 * whenever use_ntp is false, so the NTP tab sends use_ntp true and the manual
 * tab sends use_ntp false plus a timestamp.
 */
export const TimeConfigModal = ({ onClose }) => {
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
                title="Time Configurations"
                onClose={onClose}
                onSave={onClose}
                isLoading={!!loading[SECTION]}
                error={errors[SECTION]}
            />
        );
    }

    return <TimeForm stored={stored} onClose={onClose} />;
};

export default TimeConfigModal;
