import { TimeConfigModal } from "./TimeConfigModal";
import { SnmpConfigModal } from "./SnmpConfigModal";
import { SyslogConfigModal } from "./SyslogConfigModal";
import { SmtpConfigModal } from "./SmtpConfigModal";
import { SmsConfigModal } from "./SmsConfigModal";
import { CertificateConfigModal } from "./CertificateConfigModal";
import { LanguageConfigModal } from "./LanguageConfigModal";
import { RemediationConfigModal } from "./RemediationConfigModal";
import { ReportsConfigModal } from "./ReportsConfigModal";
import { DeviceKeysModal } from "./DeviceKeysModal";
import { AuthenticationConfigModal } from "./AuthenticationConfigModal";
import { DirectoryConfigModal } from "./DirectoryConfigModal";
import { CredentialProfilesModal } from "./CredentialProfilesModal";
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
 *   devicekeys  GET /api/system/device-keys  + DELETE /device-keys/{kind}  (administrators only)
 *   authentication GET/PUT /api/system/authentication + GET /authentication/users (administrators only)
 *   directory   GET/PUT /api/system/directory + POST /test, /test-user, /groups, /check (administrators only)
 *   credentials /api/credential-profiles (create, edit, delete, test: administrators only)
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
    {
        key: "reports",
        title: t("Reports"),
        hint: t("Organization name and logo on reports, and how long they are kept"),
        icon: "fa-solid fa-file-lines",
        modal: ReportsConfigModal,
    },
    {
        key: "devicekeys",
        title: t("Pinned device keys"),
        hint: t("SSH host keys and certificates of audited devices"),
        icon: "fa-solid fa-key",
        modal: DeviceKeysModal,
        adminOnly: true,
    },
    {
        key: "authentication",
        title: t("Two-step sign-in"),
        hint: t("Roles that must use a code from a phone app after the password"),
        icon: "fa-solid fa-shield-halved",
        modal: AuthenticationConfigModal,
        adminOnly: true,
    },
    {
        key: "directory",
        title: t("Active Directory / LDAP"),
        hint: t("Sign in with the organization's accounts; roles from directory groups"),
        icon: "fa-solid fa-sitemap",
        modal: DirectoryConfigModal,
        adminOnly: true,
    },
    {
        key: "credentials",
        title: t("Credential profiles"),
        hint: t("Encrypted device sign-in details for group audits and scheduled group audits"),
        icon: "fa-solid fa-id-card",
        modal: CredentialProfilesModal,
        adminOnly: true,
    },
];

export default SECTIONS;
