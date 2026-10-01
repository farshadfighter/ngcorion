import { ICON_FAMILIES } from "./assetIcons.js";
import "../../assets/AssetIcons.css";
import { t } from "../../i18n";

/** Family colour key shown on the diagram canvases. */
export function IconLegend({ showPlanned = false, families }) {
    const keys = families || Object.keys(ICON_FAMILIES).filter((k) => k !== "other");
    return (
        <div className="icon-legend" aria-label={t("Icon colours")}>
            {keys.map((k) => (
                <span key={k} className="icon-legend-item">
                    <span className="icon-legend-swatch" style={{ background: ICON_FAMILIES[k].color }} />
                    {ICON_FAMILIES[k].label}
                </span>
            ))}
            {showPlanned && (
                <span className="icon-legend-item">
                    <span className="icon-legend-swatch planned" />
                    {t("Planned")}
                </span>
            )}
        </div>
    );
}

export default IconLegend;
