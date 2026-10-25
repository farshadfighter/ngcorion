import { t } from "../../i18n";

/*
 * The recommended action of a CVE finding (app/modules/cve/recommend.py) as a sentence in the
 * interface language, built from its kind, product and target version.
 */

// Latin names and versions keep their order inside a Persian sentence.
export const iso = (s) => `\u2068${s}\u2069`;

/** The action as a sentence in the interface language. */
export function actionText(a) {
    if (!a) return "";
    const values = { product: iso(a.product || ""), version: iso(a.target || "") };
    switch (a.kind) {
        case "package":
        case "version":
            return t("Upgrade {{product}} to {{version}} or later", values);
        case "after":
            return t("Upgrade {{product}} to a version later than {{version}}", values);
        case "windows":
            return a.target ? t("Install the latest cumulative update for {{product}} (build {{version}} or later)", values)
                : t("Install the latest cumulative update for {{product}}", values);
        case "reboot":
            return t("Restart the machine: the fixed kernel {{version}} is installed but not running", values);
        default:
            return t("No fixed version is known here: follow the vendor's advisory");
    }
}
