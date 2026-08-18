import { TimeConfigModal } from "./TimeConfigModal";
import { SnmpConfigModal } from "./SnmpConfigModal";
import { SyslogConfigModal } from "./SyslogConfigModal";
import { SmtpConfigModal } from "./SmtpConfigModal";
import { SmsConfigModal } from "./SmsConfigModal";
import { CertificateConfigModal } from "./CertificateConfigModal";

/**
 * The six System Configuration cards, in Figma order.
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
 */
export const SECTIONS = [
    {
        key: "time",
        title: "Time Configurations",
        hint: "Timezone, NTP server or manual clock",
        icon: "fa-solid fa-clock",
        modal: TimeConfigModal,
    },
    {
        key: "snmp",
        title: "SNMP Configurations",
        hint: "v2c community or v3 credentials",
        icon: "fa-solid fa-network-wired",
        modal: SnmpConfigModal,
    },
    {
        key: "syslog",
        title: "Syslog Configurations",
        hint: "Remote log server and facility",
        icon: "fa-solid fa-file-lines",
        modal: SyslogConfigModal,
    },
    {
        key: "sms",
        title: "SMS Configurations",
        hint: "Provider gateway and API key",
        icon: "fa-solid fa-comment-sms",
        modal: SmsConfigModal,
    },
    {
        key: "smtp",
        title: "SMTP Configurations",
        hint: "Mail server and sender identity",
        icon: "fa-solid fa-envelope",
        modal: SmtpConfigModal,
    },
    {
        key: "certificate",
        title: "Certificate Configurations",
        hint: "TLS certificate for the web interface",
        icon: "fa-solid fa-certificate",
        modal: CertificateConfigModal,
    },
];

export default SECTIONS;
