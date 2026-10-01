import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import {
    updateAssetProfile,
    fetchZonesForDetail,
    clearProfileError,
} from "../../../store/riskDetailSlice";
import { titleCase } from "../riskConstants";
import { t } from "../../../i18n";

/** Mirrors CRITICALITY_LEVELS in app/modules/risk/schemas.py — the backend
 *  rejects anything else with a 400. Note there is no "very_high" here, even
 *  though risk_level (a computed field) does have one. */
const CRITICALITY_LEVELS = ["low", "medium", "high", "critical"];

/**
 * Edit dialog behind the two pencils in "Confidentiality & Zone".
 *
 * One dialog serves both, opened in `mode` "criticality" or "zone", because
 * PUT /api/risk/assets/{id}/profile is a single endpoint taking either field —
 * and it recalculates the risk score as part of the same request.
 */
export const EditRiskProfileModal = ({ assetId, mode, current, onClose }) => {
    const dispatch = useDispatch();
    const { zones, isSavingProfile, profileError } = useSelector(
        (state) => state.riskDetail
    );

    const isZone = mode === "zone";
    const [level, setLevel] = useState(current?.criticalityLevel || "medium");
    const [zoneId, setZoneId] = useState(
        current?.zoneId === null || current?.zoneId === undefined
            ? ""
            : String(current.zoneId)
    );
    const [reason, setReason] = useState("");

    useEffect(() => {
        if (isZone && zones.length === 0) dispatch(fetchZonesForDetail());
    }, [isZone, zones.length, dispatch]);

    // A stale error from a previous attempt must not greet the next open.
    useEffect(() => () => dispatch(clearProfileError()), [dispatch]);

    const handleSave = async () => {
        const payload = { assetId, reason: reason.trim() || undefined };
        if (isZone) {
            payload.zoneId = zoneId === "" ? null : Number(zoneId);
        } else {
            payload.criticalityLevel = level;
        }
        const res = await dispatch(updateAssetProfile(payload));
        if (updateAssetProfile.fulfilled.match(res)) onClose();
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div
                className="modal-content ard-edit-modal"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3>{isZone ? t("Edit Zone") : t("Edit Criticality")}</h3>
                    <button
                        className="modal-close"
                        onClick={onClose}
                        aria-label={t("Close")}
                    >
                        <i className="fa-solid fa-xmark" />
                    </button>
                </div>

                <div className="ard-edit-body">
                    <p className="ard-edit-note">
                        {t("Saving recalculates this asset's risk score.")}
                    </p>

                    {isZone ? (
                        <label className="ard-edit-field">
                            <span>{t("Zone")}</span>
                            <select
                                value={zoneId}
                                onChange={(e) => setZoneId(e.target.value)}
                            >
                                <option value="">{t("— No zone —")}</option>
                                {zones.map((z) => (
                                    <option key={z.id} value={z.id}>
                                        {z.name}
                                        {z.score !== undefined && z.score !== null
                                            ? t(" (score {{score}})", { score: z.score })
                                            : ""}
                                    </option>
                                ))}
                            </select>
                        </label>
                    ) : (
                        <label className="ard-edit-field">
                            <span>{t("Criticality")}</span>
                            <select
                                value={level}
                                onChange={(e) => setLevel(e.target.value)}
                            >
                                {CRITICALITY_LEVELS.map((l) => (
                                    <option key={l} value={l}>
                                        {titleCase(l)}
                                    </option>
                                ))}
                            </select>
                        </label>
                    )}

                    <label className="ard-edit-field">
                        <span>
                            {t("Reason")}{" "} <em>{t("(optional)")}</em>
                        </span>
                        <input
                            type="text"
                            maxLength={500}
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            placeholder={t("Why is this being changed?")}
                        />
                    </label>

                    {profileError && (
                        <p className="ard-edit-error">{profileError}</p>
                    )}
                </div>

                <div className="ard-edit-actions">
                    <button
                        type="button"
                        className="ard-btn ard-btn-ghost"
                        onClick={onClose}
                        disabled={isSavingProfile}
                    >
                        {t("Cancel")}
                    </button>
                    <button
                        type="button"
                        className="ard-btn ard-btn-primary"
                        onClick={handleSave}
                        disabled={isSavingProfile}
                    >
                        {isSavingProfile ? (
                            <>
                                <i className="fa-solid fa-spinner fa-spin" /> {" "}{t("Saving…")}
                            </>
                        ) : (
                            t("Save & recalculate")
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default EditRiskProfileModal;
