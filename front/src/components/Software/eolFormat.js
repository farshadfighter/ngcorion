/** Shared by the End of life page and the asset page: status labels and the sentence about the date. */
import { t } from "../../i18n";
import { formatDate } from "../../utils/dates.js";

export const EOL_STATUS = {
    unsupported: { label: t("Unsupported"), pill: "bkm-pill-bad" },
    extended: { label: t("Paid extended support only"), pill: "bkm-pill-orange" },
    ending: { label: t("Ending soon"), pill: "bkm-pill-orange" },
    supported: { label: t("Supported"), pill: "bkm-pill-ok" },
    unknown: { label: t("Not in the catalog"), pill: "bkm-pill-muted" },
};

/** The sentence under a status: when support ended, until when extended support runs, when it ends. */
export function untilText(c) {
    if (c.status === "unsupported") return c.until ? t("Support ended {{date}}", { date: formatDate(c.until) }) : t("Support has ended");
    if (c.status === "extended") return t("Extended support until {{date}}", { date: formatDate(c.until) });
    if (c.status === "ending") return t("Support ends {{date}}", { date: formatDate(c.until) });
    if (c.status === "supported") return c.until ? t("Supported until {{date}}", { date: formatDate(c.until) }) : t("No end announced");
    return "";
}
