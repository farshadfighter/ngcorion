import AssetIcon from "./AssetIcon.jsx";
import { ASSET_ICONS, ICON_KEYS } from "./assetIcons.js";
import "../../assets/AssetIcons.css";
import { t } from "../../i18n";

/**
 * Choose an icon, or "Automatic".
 *
 *   value       "" / null = automatic, otherwise an icon key
 *   automatic   the icon "Automatic" currently resolves to (shown on that tile)
 *   autoHint    where the automatic icon comes from, e.g. "from the type name"
 */
export function IconPicker({ value, onChange, automatic = "other", autoHint, label = "Icon" }) {
    const current = value || "";
    return (
        <div className="icon-picker-wrap">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: "#374151" }}>{label}</span>
                <span className="icon-picker-suggest">
                    {t("Automatic:")}{" "} {ASSET_ICONS[automatic]?.label || t("Other")}{autoHint ? ` (${autoHint})` : ""}
                </span>
            </div>
            <div className="icon-picker" role="radiogroup" aria-label={label}>
                <button
                    type="button"
                    role="radio"
                    aria-checked={current === ""}
                    className={`icon-picker-option ${current === "" ? "on" : ""}`}
                    onClick={() => onChange("")}
                >
                    <AssetIcon icon={automatic} size={36} />
                    <span>{t("Automatic")}</span>
                </button>
                {ICON_KEYS.map((k) => (
                    <button
                        key={k}
                        type="button"
                        role="radio"
                        aria-checked={current === k}
                        className={`icon-picker-option ${current === k ? "on" : ""}`}
                        onClick={() => onChange(k)}
                    >
                        <AssetIcon icon={k} size={36} />
                        <span>{ASSET_ICONS[k].label}</span>
                    </button>
                ))}
            </div>
        </div>
    );
}

export default IconPicker;
