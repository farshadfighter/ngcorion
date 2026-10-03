"""
Which NVD product an installed package or Windows program is.

A package name (dpkg/rpm) or a Windows DisplayName is reduced to a match key
("Mozilla Firefox (x64 en-US)" -> "mozilla firefox", "postgresql-16" stays),
then looked up in:
  1. the mappings an admin made (SoftwareProductMap), fleet-wide;
  2. the built-in catalog below - common server and desktop software whose
     NVD vendor:product names are well known.
Anything else is "unidentified" until someone maps it (or marks it internal).

CPE names are NVD's own, escapes included ("notepad\\+\\+"), because the
local CVE database stores them exactly as NVD writes them. A product can
carry more than one CPE when NVD has filed it under two vendors over time
(nginx:nginx and later f5:nginx).
"""
import re
from typing import Dict, List, Optional, Tuple

CPE = Tuple[str, str]

# Readable label, then the CPEs. Keys are match keys (see match_key).
_EXACT: Dict[str, Tuple[str, List[CPE]]] = {}
# (pattern over the match key, label, CPEs) for families: postgresql-16, php8.3-fpm, ...
_PATTERNS: List[Tuple[re.Pattern, str, List[CPE]]] = []


def _add(names, label, *cpes):
    for n in names.split("|"):
        _EXACT[n] = (label, list(cpes))


def _pat(regex, label, *cpes):
    _PATTERNS.append((re.compile(regex), label, list(cpes)))


# ── server software (Linux package names, also Windows names where equal) ──
_add("openssh-server|openssh-client|openssh|openssh-clients", "OpenSSH", ("openbsd", "openssh"))
_add("openssl", "OpenSSL", ("openssl", "openssl"))
_add("nginx|nginx-core|nginx-full|nginx-light|nginx-extras|nginx-plus", "nginx", ("f5", "nginx"), ("nginx", "nginx"))
_add("apache2|httpd|apache http server", "Apache HTTP Server", ("apache", "http_server"))
_add("tomcat|tomcat9|tomcat10|apache tomcat", "Apache Tomcat", ("apache", "tomcat"))
_add("mysql-server|mysql-community-server|mysql-server-core|mysql server", "MySQL", ("oracle", "mysql"))
_add("mariadb-server|mariadb", "MariaDB", ("mariadb", "mariadb"))
_add("postgresql|postgresql-server", "PostgreSQL", ("postgresql", "postgresql"))
_add("redis|redis-server", "Redis", ("redis", "redis"))
_add("mongodb-org-server|mongodb-org|mongodb-server|mongodb|mongodb server", "MongoDB", ("mongodb", "mongodb"))
_add("docker-ce|docker-ce-cli|docker.io|docker-engine|moby-engine|moby-cli|docker", "Docker Engine", ("docker", "docker"),
     ("mobyproject", "moby"))
_add("docker-compose-plugin|docker-compose", "Docker Compose", ("docker", "compose"))
_add("containerd.io|containerd", "containerd", ("linuxfoundation", "containerd"))
_add("runc", "runc", ("linuxfoundation", "runc"))
_add("kubelet|kubeadm|kubectl|kubernetes", "Kubernetes", ("kubernetes", "kubernetes"))
_add("nodejs|node.js", "Node.js", ("nodejs", "node.js"))
_add("git|git-core", "Git", ("git-scm", "git"))
_add("curl", "curl", ("haxx", "curl"))
_add("sudo", "sudo", ("sudo_project", "sudo"))
_add("bash", "GNU Bash", ("gnu", "bash"))
_add("bind9|bind", "ISC BIND", ("isc", "bind"))
_add("isc-dhcp-server|dhcp-server", "ISC DHCP", ("isc", "dhcp"))
_add("samba", "Samba", ("samba", "samba"))
_add("vsftpd", "vsftpd", ("beasts", "vsftpd"))
_add("proftpd-basic|proftpd|proftpd-core", "ProFTPD", ("proftpd", "proftpd"))
_add("postfix", "Postfix", ("postfix", "postfix"))
_add("exim4|exim4-daemon-light|exim4-daemon-heavy|exim", "Exim", ("exim", "exim"))
_add("dovecot-core|dovecot", "Dovecot", ("dovecot", "dovecot"))
_add("squid", "Squid", ("squid-cache", "squid"))
_add("haproxy", "HAProxy", ("haproxy", "haproxy"))
_add("openvpn", "OpenVPN", ("openvpn", "openvpn"))
_add("strongswan", "strongSwan", ("strongswan", "strongswan"))
_add("grafana|grafana-enterprise", "Grafana", ("grafana", "grafana"))
_add("prometheus", "Prometheus", ("prometheus", "prometheus"))
_add("elasticsearch", "Elasticsearch", ("elastic", "elasticsearch"))
_add("kibana", "Kibana", ("elastic", "kibana"))
_add("logstash", "Logstash", ("elastic", "logstash"))
_add("jenkins", "Jenkins", ("jenkins", "jenkins"))
_add("gitlab-ce|gitlab-ee", "GitLab", ("gitlab", "gitlab"))
_add("zabbix-agent|zabbix-agent2|zabbix-server-mysql|zabbix-server-pgsql|zabbix-proxy-mysql|zabbix-proxy-sqlite3"
     "|zabbix agent|zabbix agent 2", "Zabbix", ("zabbix", "zabbix"))
_add("wazuh-agent|wazuh-manager|wazuh agent", "Wazuh", ("wazuh", "wazuh"))
_add("rabbitmq-server", "RabbitMQ", ("vmware", "rabbitmq"), ("pivotal_software", "rabbitmq"))
_add("erlang", "Erlang/OTP", ("erlang", "erlang\\/otp"))
_add("memcached", "Memcached", ("memcached", "memcached"))
_add("vim", "Vim", ("vim", "vim"))
_add("slapd|openldap-servers", "OpenLDAP", ("openldap", "openldap"))
_add("cups", "CUPS", ("openprinting", "cups"), ("apple", "cups"))
_add("influxdb|influxdb2", "InfluxDB", ("influxdata", "influxdb"))
_add("telegraf", "Telegraf", ("influxdata", "telegraf"))
_add("consul", "Consul", ("hashicorp", "consul"))
_add("vault", "Vault", ("hashicorp", "vault"))
_add("nomad", "Nomad", ("hashicorp", "nomad"))
_add("terraform", "Terraform", ("hashicorp", "terraform"))
_add("teleport", "Teleport", ("gravitational", "teleport"))
_add("webmin", "Webmin", ("webmin", "webmin"))
_add("phpmyadmin", "phpMyAdmin", ("phpmyadmin", "phpmyadmin"))
_add("roundcube|roundcube-core", "Roundcube", ("roundcube", "webmail"))
_add("splunk", "Splunk", ("splunk", "splunk"))
_add("splunkforwarder|universalforwarder", "Splunk Universal Forwarder", ("splunk", "universal_forwarder"))
_add("snmpd|net-snmp", "Net-SNMP", ("net-snmp", "net-snmp"))
_add("ntp|ntpd", "NTP", ("ntp", "ntp"))
_add("chrony", "chrony", ("tuxfamily", "chrony"))
_add("rsync", "rsync", ("samba", "rsync"))
_add("xrdp", "xrdp", ("neutrinolabs", "xrdp"))
_add("cockpit|cockpit-ws", "Cockpit", ("cockpit-project", "cockpit"))
_add("keepalived", "Keepalived", ("keepalived", "keepalived"))
_add("unbound", "Unbound", ("nlnetlabs", "unbound"))
_add("pdns-server", "PowerDNS Authoritative Server", ("powerdns", "authoritative_server"))
_add("pdns-recursor", "PowerDNS Recursor", ("powerdns", "recursor"))
_add("dnsmasq", "dnsmasq", ("thekelleys", "dnsmasq"))
_add("clamav|clamav-daemon", "ClamAV", ("clamav", "clamav"))
_add("fail2ban", "Fail2ban", ("fail2ban", "fail2ban"))
_add("nagios|nagios4", "Nagios", ("nagios", "nagios"))
_add("icinga2", "Icinga 2", ("icinga", "icinga"))
_add("openvswitch-switch|openvswitch", "Open vSwitch", ("openvswitch", "openvswitch"))
_add("qemu-system-x86|qemu-kvm", "QEMU", ("qemu", "qemu"))
_add("libvirt-daemon|libvirt-daemon-system", "libvirt", ("redhat", "libvirt"))
_add("powershell", "PowerShell", ("microsoft", "powershell"))
_add("dotnet-runtime|aspnetcore-runtime|microsoft .net runtime|microsoft asp.net core runtime",
     ".NET", ("microsoft", ".net"))
_add("google-chrome-stable|google chrome", "Google Chrome", ("google", "chrome"))
_add("firefox|firefox-esr|mozilla firefox|mozilla firefox esr", "Mozilla Firefox", ("mozilla", "firefox"))
_add("thunderbird|mozilla thunderbird", "Mozilla Thunderbird", ("mozilla", "thunderbird"))
_add("code|microsoft visual studio code|visual studio code", "Visual Studio Code",
     ("microsoft", "visual_studio_code"))
_add("teamviewer|teamviewer host", "TeamViewer", ("teamviewer", "teamviewer"))
_add("anydesk", "AnyDesk", ("anydesk", "anydesk"))
_add("zoom|zoom workplace", "Zoom", ("zoom", "zoom"))
_add("virtualbox|oracle vm virtualbox", "VirtualBox", ("oracle", "vm_virtualbox"))
_add("wireshark", "Wireshark", ("wireshark", "wireshark"))
_add("libreoffice", "LibreOffice", ("libreoffice", "libreoffice"))
_add("keepass|keepass password safe", "KeePass", ("keepass", "keepass"))

# ── Windows programs (DisplayName match keys) ──────────────────────────────
_add("microsoft edge", "Microsoft Edge", ("microsoft", "edge_chromium"))
_add("7-zip", "7-Zip", ("7-zip", "7-zip"))
_add("notepad++", "Notepad++", ("notepad-plus-plus", "notepad\\+\\+"))
_add("winrar", "WinRAR", ("rarlab", "winrar"))
_add("adobe acrobat reader|adobe acrobat reader dc|adobe acrobat dc|adobe acrobat", "Adobe Acrobat Reader",
     ("adobe", "acrobat_reader_dc"), ("adobe", "acrobat_reader"))
_add("vlc media player", "VLC media player", ("videolan", "vlc_media_player"))
_add("putty", "PuTTY", ("putty", "putty"), ("simon_tatham", "putty"))
_add("winscp", "WinSCP", ("winscp", "winscp"))
_add("filezilla client|filezilla", "FileZilla Client", ("filezilla-project", "filezilla_client"))
_add("filezilla server", "FileZilla Server", ("filezilla-project", "filezilla_server"))
_add("forticlient|forticlient vpn", "FortiClient", ("fortinet", "forticlient"))
_add("citrix workspace", "Citrix Workspace", ("citrix", "workspace"))
_add("vmware tools", "VMware Tools", ("vmware", "tools"))
_add("vmware workstation", "VMware Workstation", ("vmware", "workstation"))
_add("tortoisegit", "TortoiseGit", ("tortoisegit", "tortoisegit"))
_add("python", "Python", ("python", "python"))
_add("php", "PHP", ("php", "php"))
_add("openjdk", "OpenJDK", ("oracle", "openjdk"))
_add("java|java runtime environment", "Java Runtime", ("oracle", "jre"))
_add("java se development kit|java(tm) se development kit", "Java SE Development Kit", ("oracle", "jdk"))

# ── device firmware, as the Cisco and Fortinet audits name it ────────────
_add("cisco ios xe", "Cisco IOS XE", ("cisco", "ios_xe"))
_add("cisco ios", "Cisco IOS", ("cisco", "ios"))
_add("cisco nx-os", "Cisco NX-OS", ("cisco", "nx-os"))
_add("cisco asa", "Cisco ASA", ("cisco", "adaptive_security_appliance_software"))
_add("fortinet fortios", "Fortinet FortiOS", ("fortinet", "fortios"))

# ── families ─────────────────────────────────────────────────────────────
_pat(r"^postgresql-\d+(\.\d+)?$|^postgresql\d+-server$|^postgresql \d+$", "PostgreSQL", ("postgresql", "postgresql"))
_pat(r"^mysql-server-\d+\.\d+$|^mysql server \d+\.\d+$", "MySQL", ("oracle", "mysql"))
_pat(r"^mariadb-server-\d+\.\d+$", "MariaDB", ("mariadb", "mariadb"))
_pat(r"^php\d+(\.\d+)?(-cli|-fpm|-cgi)?$|^php\d+(\.\d+)?$", "PHP", ("php", "php"))
_pat(r"^python\d(\.\d+)?$|^python \d+\.\d+", "Python", ("python", "python"))
_pat(r"^openjdk-\d+-(jre|jdk)(-headless)?$|^java-\d+(\.\d+)*-openjdk(-headless|-devel)?$", "OpenJDK",
     ("oracle", "openjdk"))
_pat(r"^java \d+ update \d+", "Java Runtime", ("oracle", "jre"))
_pat(r"^microsoft sql server (20\d\d)", "Microsoft SQL Server {1}", ("microsoft", "sql_server_{1}"))
_pat(r"^tomcat\d+$", "Apache Tomcat", ("apache", "tomcat"))
_pat(r"^redis\d*-server$|^redis\d+$", "Redis", ("redis", "redis"))
_pat(r"^zabbix-(agent|server|proxy)", "Zabbix", ("zabbix", "zabbix"))
_pat(r"^elasticsearch-\d", "Elasticsearch", ("elastic", "elasticsearch"))

# Dependency-only packages: stored, never listed as products on their own.
_COMPONENT = re.compile(
    r"^(lib|fonts-|gir\d|linux-(headers|modules|tools|image|cloud-tools)|python3-|perl-|ruby-|node-|golang-"
    r"|x11-|xserver-|language-pack|ca-certificates|tzdata|locales|manpages|dictionaries-)"
    r"|(-common|-doc|-data|-dev|-devel|-dbg|-dbgsym|-headers|-locale|-l10n|-man|-examples)$"
    r"|^microsoft visual c\+\+ \d{4}|^microsoft \.net (framework|host|sdk|toolset|targeting|apphost|templates)"
    r"|^windows (sdk|software development kit)|redistributable|^update for |^security update for "
    r"|^docker-(buildx-plugin|ce-rootless-extras|scan-plugin)$|webview2|update health tools|^microsoft edge update")


_PARENS = re.compile(r"\([^)]*\)")
_VERSIONISH = re.compile(r"\b(v?\d+(\.\d+)+[a-z0-9.\-]*|\d{4})\b")
_NOISE = re.compile(r"\b(x64|x86|amd64|arm64|64-bit|32-bit|en-us|en-gb|\d+-bit)\b")


def match_key(name: str, windows: bool = False) -> str:
    """The name used for catalog lookup and admin mappings."""
    key = (name or "").strip().lower()
    if not windows:
        return re.sub(r":[a-z0-9_]+$", "", key)          # dpkg arch qualifier "libc6:amd64"
    key = _PARENS.sub(" ", key)
    key = _NOISE.sub(" ", key)
    # "Microsoft SQL Server 2019" keeps its year; other trailing versions go.
    keep_year = re.match(r"^microsoft sql server 20\d\d", key)
    if not keep_year:
        key = _VERSIONISH.sub(" ", key)
    key = re.sub(r"\s+-\s*$|\s+", " ", key).strip(" -")
    return key


def is_component(key: str) -> bool:
    return bool(_COMPONENT.search(key))


def lookup(key: str) -> Optional[Tuple[str, List[CPE]]]:
    """(label, [cpe]) from the built-in catalog, or None."""
    hit = _EXACT.get(key)
    if hit:
        return hit
    for pattern, label, cpes in _PATTERNS:
        m = pattern.search(key)
        if m:
            group = m.group(1) if m.groups() and m.group(1) else None
            filled = [(v, p.replace("{1}", group) if group else p) for v, p in cpes]
            return (label.replace("{1}", group) if group else label), filled
    return None


def catalog_size() -> int:
    return len({label for label, _ in _EXACT.values()} | {label for _, label, _ in _PATTERNS})


def upstream_version(version: Optional[str], kind: str = "deb") -> Optional[str]:
    """The upstream version NVD ranges are written in.

    deb  1:6.4.10-1+ubuntu22.04 -> 6.4.10 ; 5:24.0.7-1~ubuntu.22.04~jammy -> 24.0.7
    rpm  1:2.4.57-5.el9 -> 2.4.57 (the form arrives as epoch:version-release)
    other kinds (Windows, services, firmware) are used as they are."""
    if not version:
        return None
    v = version.strip()
    if kind in ("deb", "rpm"):
        v = re.sub(r"^\d+:", "", v)
        if "-" in v:
            v = v.rsplit("-", 1)[0]
        v = re.split(r"[~+]", v, 1)[0]
        v = re.sub(r"\.(dfsg|ds|really)\d*$", "", v)
    return v or None
