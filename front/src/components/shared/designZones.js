import { t } from "../../i18n";
// Mirrors app/modules/design/templates.py's ZONES dict exactly, so the
// zone bands drawn behind Suggested Design's nodes use the same id/label
// pairing the backend already assigns each component to - same convention
// as assetIcons.js mirroring app/core/asset_icons.py's keyword rules.
export const ZONES = {
    internet_edge: { label: t("Internet Edge"), color: "#eef2ff", border: "#c7d2fe" },
    dmz: { label: t("DMZ"), color: "#fff7ed", border: "#fed7aa" },
    core: { label: t("Core"), color: "#eef6ff", border: "#bfdbfe" },
    distribution: { label: t("Distribution"), color: "#ecfdf5", border: "#a7f3d0" },
    access: { label: t("Access"), color: "#f0fdf4", border: "#bbf7d0" },
    data_center: { label: t("Data Center"), color: "#fdf4ff", border: "#e9d5ff" },
};

export default ZONES;
