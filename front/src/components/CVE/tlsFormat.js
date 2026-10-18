/** Shared by the TLS certificates page and the asset page: levels, scan states and the sentence of each problem. */
import { t, n } from "../../i18n";
import { formatDate } from "../../utils/dates.js";

export const LEVEL = {
    critical: { label: t("Expired"), pill: "bkm-pill-bad" },
    warning: { label: t("Has problems"), pill: "bkm-pill-orange" },
    ok: { label: t("No problem"), pill: "bkm-pill-ok" },
    unknown: { label: t("Not read yet"), pill: "bkm-pill-muted" },
};

export const SCAN_STATUS = {
    pending: t("Waiting for the scan"),
    read: t("Certificate read"),
    unreachable: t("No answer"),
    no_tls: t("Not a TLS service"),
};

/** OpenSSL's protocol names as people say them. */
export const PROTOCOL = { TLSv1: "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3" };
export const protocolName = (p) => PROTOCOL[p] || p;

/** One problem as a short sentence. */
export function problemText(p) {
    switch (p.code) {
        case "expired": return t("Expired {{date}}", { date: formatDate(p.date) });
        case "expiring": return t("Expires {{date}}, in {{days}} days", { date: formatDate(p.date), days: n(p.days) });
        case "not_yet_valid": return t("Not valid before {{date}}", { date: formatDate(p.date) });
        case "untrusted": return p.self_signed ? t("Self-signed") : t("Issued by an untrusted authority");
        case "weak_key": return t("Weak key: {{key}}", { key: p.key });
        case "weak_signature": return t("Signed with {{algorithm}}", { algorithm: p.algorithm });
        case "old_protocol": return t("Accepts {{protocols}}", { protocols: p.protocols.join(t(", ")) });
        case "name_mismatch": return t("Does not name the host");
        default: return p.code;
    }
}

/** What to do about it, shown in the service drawer. */
export function problemHelp(p) {
    switch (p.code) {
        case "expired": return t("Clients refuse the service or warn their users. Renew the certificate and install it on the device.");
        case "expiring": return t("Renew it before that day; on many devices the new certificate has to be installed by hand.");
        case "not_yet_valid": return t("Check the device's clock, or the certificate was installed too early.");
        case "untrusted": return p.self_signed
            ? t("Users learn to click through browser warnings. Install a certificate from the organisation's CA, or trust that CA here if it is one.")
            : t("The issuer is neither a public authority nor one of the organisation's trusted authorities (Settings). Add the organisation's CA, or check that the server sends its intermediate certificates.");
        case "weak_key": return t("Issue a new certificate with an RSA key of at least 2048 bits or an EC key.");
        case "weak_signature": return t("Issue a new certificate signed with SHA-256 or stronger.");
        case "old_protocol": return t("Turn off TLS 1.0 and 1.1 on the service; every current client speaks TLS 1.2 or 1.3.");
        case "name_mismatch": return t("The certificate is for another name than the asset's host name: clients that check the name refuse it.");
        default: return "";
    }
}

/** The common name of a subject or issuer ("CN=fw.corp.local,O=Corp" -> "fw.corp.local"). */
export function commonName(dn) {
    if (!dn) return "—";
    const m = /(?:^|,)CN=((?:\\,|[^,])+)/.exec(dn);
    return m ? m[1].replace(/\\,/g, ",") : dn;
}
