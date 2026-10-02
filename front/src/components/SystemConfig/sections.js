import { TimeConfigModal } from "./TimeConfigModal";
import { SnmpConfigModal } from "./SnmpConfigModal";
import { SyslogConfigModal } from "./SyslogConfigModal";
import { SmtpConfigModal } from "./SmtpConfigModal";
import { SmsConfigModal } from "./SmsConfigModal";
import { CertificateConfigModal } from "./CertificateConfigModal";
import { LanguageConfigModal } from "./LanguageConfigModal";
import { RemediationConfigModal } from "./RemediationConfigModal";
import { t } from "../../i18n";

/**
 * The System Configuration cards.
 *
 * Endpoints are listed for reference; each modal owns its own calls.
 *
 *   time        GET/PUT /api/system/time
 *   snmp        GET/PUT /api/system/snmp
 *   syslog      GET/PUT /api/system/syslog
 *   sms         GET/PUT /api/system/sms      + POST /sms/test
 *   smtp        GET/PUT /api/system/smtp     + POST /smtp/test
 *   certificate GET /api/system/certificate  + POST /certificate/upload
 *                                            + DELETE /certificate
 *   locale      GET/PUT /api/system/locale   (default language)
 */
export const SECTIONS = [
    {
        key: "time",
        title: t("Time Configurations"),
        hint: t("Timezone, NTP server or manual clock"),
        icon: "fa-solid fa-clock",
        modal: TimeConfigModal,
    },
    {
        key: "snmp",
        title: t("SNMP Configurations"),
        hint: t("Server address, v2c community or v3 credentials"),
        icon: "fa-solid fa-network-wired",
        modal: SnmpConfigModal,
    },
    {
        key: "syslog",
        title: t("Syslog Configurations"),
        hint: t("Remote log server and facility"),
        icon: "fa-solid fa-file-lines",
        modal: SyslogConfigModal,
    },
    {
        key: "sms",
        title: t("SMS Configurations"),
        hint: t("Provider gateway and API key"),
        icon: "fa-solid fa-comment-sms",
        modal: SmsConfigModal,
    },
    {
        key: "smtp",
        title: t("SMTP Configurations"),
        hint: t("Mail server and sender identity"),
        icon: "fa-solid fa-envelope",
        modal: SmtpConfigModal,
    },
    {
        key: "certificate",
        title: t("Certificate Configurations"),
        hint: t("TLS certificate for the web interface"),
        icon: "fa-solid fa-certificate",
        modal: CertificateConfigModal,
    },
    {
        key: "locale",
        title: t("Language"),
        hint: t("Default interface language for new users"),
        icon: "fa-solid fa-language",
        modal: LanguageConfigModal,
    },
    {
        key: "remediation",
        title: t("Remediation deadlines"),
        hint: t("Days to fix each severity, and the longest risk acceptance"),
        icon: "fa-solid fa-clipboard-check",
        modal: RemediationConfigModal,
    },
];

export default SECTIONS;
