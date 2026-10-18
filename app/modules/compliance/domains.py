"""
Security domains: the layer between audit checks and the requirements of compliance standards.

Every check of every benchmark (2,000+ over 17 modules, numbered differently by each benchmark and
edition) is put in one or more domains from its title (password, audit log, TLS ...); every requirement
of a standard (app/modules/compliance/standards/*.json) names the domains that give evidence for it.
So a standard covers every module, today's and tomorrow's, without a check-by-check table that breaks
when a benchmark renumbers. An administrator can correct the domains of a single check
(ComplianceCheckDomains overrides this classification), and a requirement may also name checks directly.

The classification is a heuristic: it says which checks are evidence for a requirement, not that the
requirement is met by them alone. Requirements no check covers are assessed by hand.
"""
import re
from typing import Dict, List, Optional, Tuple

# key -> English name (the frontend translates it). Order is the order shown.
DOMAINS: Dict[str, str] = {
    "accounts": "Accounts and privileges",
    "authentication": "Authentication and passwords",
    "remote_access": "Remote administration",
    "session": "Session lock and logon notice",
    "logging": "Audit logging",
    "time": "Clock synchronisation",
    "services": "Unneeded services and software",
    "network_filtering": "Firewall and network filtering",
    "network_hardening": "Network protocol hardening",
    "crypto": "Encryption in transit",
    "data_protection": "Data at rest and secrets",
    "filesystem": "File permissions and storage",
    "integrity": "Integrity and secure boot",
    "isolation": "Process isolation and exploit protection",
    "malware": "Malware protection",
    "patching": "Updates and supported versions",
    "web_hardening": "Web server hardening",
    "availability": "Resource limits and availability",
}

# (domain, pattern on the lower-cased title). A title gets every domain whose pattern matches.
_RULES: List[Tuple[str, str]] = [
    ("authentication", r"sid filtering|null session|\bspn\b|target name validation|pwquality|complexity|minclass|minlen|authselect|authorization-mode|machinekey|ctrl\+alt\+del|logons to cache|cached logon|interactive login|nologin|/etc/shells|\bpass_|password|passphrase|\bpam\b|pam_|faillock|lockout|lock ?out|failed log(?:i|o)n|"
                       r"login attempts|logon attempts|authenticat|kerberos|\bntlm|lan manager|lm hash|"
                       r"credential|\bscram|\bmfa\b|multi-?factor|two-?factor|\btotp|token-auth|"
                       r"\bhashing|crypt\b|yescrypt|sha-?512|\baaa\b|tacacs|radius|\bldap|anonymous (?:bind|access|"
                       r"logon|sid)|empty password|blank password|certificate binding|smart ?card|"
                       r"account lockout|reversible encryption|\bpki\b|client cert"),
    ("accounts", r"access is limited|access is restricted|allowusers|allowgroups|trustworthy|machineaccountquota|external trusts|authorization for|\bdefiner\b|invoker|minimize access|access to (?:secrets|create|the cluster)|force shutdown|back up files|restore files|shut down the system|change the system time|create (?:a )?(?:pagefile|token|symbolic|global|permanent)|load and unload|manage auditing|modify (?:an object|firmware)|profile (?:single|system)|replace a process|generate security audits|increase (?:a process|scheduling)|lock pages|perform volume|synchronize directory|enable computer|add workstations|adjust memory|access this computer|access credential manager|trusted caller|bypass traverse|\baccount|\busers?\b|user's|\buid\b|\bgid\b|\bgroups?\b|\broot\b|\badmin(?:istrator)?s?\b|"
                 r"privileg|\bsudo|\bsu\b|\bwheel|\bgrant\b|grant option|\brole|rbac|super_?priv|\bsa\b login|"
                 r"guest|service account|\bsysadmin|least privilege|\bowner(?:ship)? (?:of|is) (?:the )?database|"
                 r"user rights|right to|(?:allow|deny) log ?on|log on as|act as part|debug programs|"
                 r"take ownership|impersonat|elevat|\buac\b|user account control|home director|dot ?files|"
                 r"\.netrc|\.rhosts|\.forward\b|shadow group|duplicate (?:uid|gid|user|group)|inactive|"
                 r"default (?:user|account|password)|enable secret|username|delegat|trusted for|"
                 r"cluster-?admin|anonymous|\bdba\b|public role|\bpublic\b.*permission"),
    ("remote_access", r"\bssh|sshd|\brdp\b|remote desktop|terminal serv|\bwinrm|\btelnet|\bvty\b|\bline vty|"
                      r"remote (?:access|administration|management|registry|assistance|shell)|"
                      r"management (?:interface|service|access|port|plane)|admin(?:istrative)? (?:access|"
                      r"interface|port|https|http|gui|console)|\bconsole|trusted host|admin-?port|"
                      r"\bhttps? (?:admin|management)|web ui|webui|exec-timeout|\bdcui\b|esxi shell|"
                      r"lockdown mode|\bapi server|--anonymous-auth|kubelet.*auth|xdmcp|rlogin|rsh\b|"
                      r"remote access"),
    ("session", r"times? out|message of the day|last signed-in|display last|logon hours expire|timeout|time-?out|idle|inactivity|screen ?saver|screen lock|lock screen|session (?:lock|"
                r"limit|termination)|\bbanner|\bmotd\b|/etc/issue|message (?:title|text)|logon message|"
                r"warning message|login message|legal notice|exec-timeout|clientaliveinterval|logingracetime|"
                r"\btmout\b"),
    ("logging", r"loglevel|log level|\baudit|events? (?:that|are|is) .*collected|\bcollected\b|log_error|log_warnings|general_log|\baudit(?:d|ing| log| polic| record| rule|s? (?:the|events|account|logon|policy|process|"
                r"object|privilege|system|detailed|ds|other|security|special|user|sensitive|file|"
                r"registry|removable|credential|kerberos|directory|group|computer|logoff|account)|\b)|"
                r"\blog(?:s|ging|ged|file|rotate)?\b(?! ?on\b| ?off\b)|syslog|rsyslog|journald|journal\b|event ?log|"
                r"\bevent (?:record|capture)|eventrecordqps|access log|error log|\btrap|\bsiem|"
                r"logon events|record events|archiv(?:e|ing) log|log retention|log size|maximum log"),
    ("time", r"\bntp\b|\bntpd|chrony|timesyncd|time ?synchroni|time source|time server|clock|\bw32time|"
             r"time zone|timezone|time stamp|timestamp"),
    ("services", r"profiling|rest api|managed object browser|\bmob\b|dvfilter|identd|\binterface tunnel|\bgzip|hidden file|enclosures|\brss\b|read-only-port|sprawl|auto_close|not (?:be )?installed|is not enabled|are not enabled|not running|is disabled\b.*(?:service|"
                 r"server|daemon)|unnecessary|unused|not available|(?:service|server|daemon|module|protocol"
                 r"|feature|role|plugin|extension|component|package)s? (?:is|are) (?:disabled|removed|not)|"
                 r"\bdisable (?:the )?(?:unused|unnecessary)|avahi|\bcups\b|\bdhcp server is not|"
                 r"\bftp\b|\btftp\b|\bnfs\b|\bnis\b|\bsamba\b|\bsnmp(?:d)? (?:server|service) is|"
                 r"xinetd|inetd|rpcbind|\bslapd\b|\bdovecot|squid|\bhttp(?:d)? server is|webdav|"
                 r"autodir|autofs|dccp|sctp|\brds\b|\btipc\b|bluetooth|wireless|usb|removable|"
                 r"cramfs|freevxfs|jffs2|hfs|squashfs|udf|\bfloppy|serial|parallel|cdrom|cd-?rom|"
                 r"\bmodules? (?:is|are) disabled|\bmod_|sample|example|default (?:content|page|site|"
                 r"database)|test database|demo|\bxp_cmdshell|clr enabled|ole automation|"
                 r"ad hoc distributed|cross db|database mail|remote access' is set|scan for startup|"
                 r"\bcdp\b|ip source-route|service pad|bootp|finger|small servers|\bhttp server\b|"
                 r"\bjsonp\b|rest interface|scripting|server-side scripting|cgi|\bisapi|directory browsing|"
                 r"\bdirectory listing|autoindex|\bwebdav|onedrive|cortana|telemetry|consumer experience|"
                 r"game|store app|print spooler|xbox"),
    ("network_filtering", r"traffic is restricted|ports are open|open ports|needed ports|\blistens\b|listening|hostports?|ip address based requests|bound to a specific|ip address restrictions|dynamic ip|bind-?address|interface binding|accessible from|exposed|reachable|internet|firewall|\bfirewalld|iptables|ip6tables|nftables|\bufw\b|\bacl\b|access-list|"
                          r"access control list|access-group|\bpolic(?:y|ies) (?:deny|allow|rule)|"
                          r"(?:deny|drop|reject) (?:all|by default|traffic|policy)|default (?:deny|drop)|"
                          r"inbound|outbound|ingress|egress|allowlist|whitelist|restrict(?:ed|s)? (?:network |inbound |outbound )?"
                          r"(?:traffic|access from|connections)|bind(?:s|-address)? to|listen(?:s|ing)? (?:only|on)|"
                          r"authorized ports|trusted (?:hosts?|network)|\bzone transfer|recursion|"
                          r"allow-transfer|network ?polic|\bwan\b|segment|vlan|\bdmz|"
                          r"hostbasedauthentication|bindaddress|local ?host only|loopback"),
    ("network_hardening", r"directed broadcast|source ?routing|domain-name|control-plane|address-family|autonomous-system|af-interface|eigrp|\bospf|\bbgp|\brouting|key chain|mac address change|forged transmits|promiscuous|userland proxy|non-standard port|cached records|\bport\b.*(?:default|standard)|\bipv4\b|ip ?forward|forwarding|redirect|source[- ]rout|router advertisement|"
                          r"\bicmp|syn ?cookie|tcp_syncookies|rp_filter|reverse path|martian|"
                          r"suspicious packet|\bipv6\b|\bsnmp|community|\blldp\b|\bcdp\b|\bdns\b|\bdnssec|"
                          r"\bdhcp\b|\barp\b|proxy arp|\bnetbios|llmnr|\bmdns|\bwpad|\bsmb ?v?1|smbv1|"
                          r"\bspanning|bpdu|\bport security|\bstorm|\bunicast rpf|\burpf|ip directed|"
                          r"\bgratuitous|\bbridge|bridged|rate limit.*packet|ttl|ip options|"
                          r"\bnet\.ipv[46]|network (?:parameter|setting|stack)|sctp|dccp|\brds\b|tipc|"
                          r"hostname|domain name|\bwins\b|link-local"),
    ("crypto", r"ssh protocol|protocol is set to 2|session resumption|forward secrecy|certfile|keyfile|cafile|tls-cert|kubelet-certificate|--client-ca|rotate-certificates|rotatekubeletservercertificate|\btls\b|tlsv|\bssl\b|sslv|\bcipher|encrypt(?:ed|ion)? (?:in transit|traffic|connection|"
               r"channel|communications|transport|session)|\bhttps\b|\bhsts|strict-transport|\bmac(?:s)?\b "
               r"(?:are|is) configured|\bkex|key ?exchange|kexalgorithms|hostkey|\bcertificate|\bcert\b|"
               r"\bpki\b|digitally (?:sign|encrypt)|signing|signed (?:communications|ldap)|\bsign "
               r"communications|seal|\bsnmpv3|\bv3\b|strong (?:key|crypto|cipher)|weak (?:cipher|"
               r"crypto|protocol|algorithm)|\bdes\b|\b3des|\brc4|\bmd5|\bsha-?1\b|diffie|\bdh\b param|"
               r"\becdhe|\bfips|crypto|static keys|ssl-?verify|verify[_ ]server[_ ]cert|require[_ ]secure"
               r"[_ ]transport|sslmode|\bipsec|\bvpn\b|ike\b|\bpsk\b|private key|key size|key length|"
               r"\bocsp|stapling|\bssl_|\bsession ticket|\bencrypt"),
    ("data_protection", r"hashing algorithm|password hash|point-in-time recovery|tombstone|command history|\bhistory\b|\bmysql_history|password(?:s)? (?:in|on) the command|at rest|\btde\b|transparent data encryption|encrypt(?:ed|ion)? (?:at rest|data|"
                        r"database|backup|disk|volume|storage|swap|secrets)|\bbitlocker|\bluks|"
                        r"backup|keyring|\bsecret|stored (?:password|credential)|storage of passwords|"
                        r"clear ?text|plain ?text|\bnetrc|\bpassword-encryption|service password-encryption|"
                        r"masking|data leak|core dump|crash dump|pagefile|swap file|hibernat|"
                        r"\bkms\b|key management|etcd.*encrypt|encryption-provider|\bvault"),
    ("web_hardening", r"default html|html content|\boptions for|\boptions directive|modsecurity|core rule set|non-ascii|\burls?\b|error and index|index\.html|scoreboard|source ip information|x-content-type-options|x-frame-options|content-security-policy|referrer-policy|"
                      r"\bheader|framing|\bclickjack|double-encoded|request filter|request smuggl|"
                      r"\bhttp (?:method|verb)|\btrace method|\btrace\b|options method|\boverride|"
                      r"allowoverride|servertokens|serversignature|server_tokens|x-powered-by|"
                      r"\bcookie|httponly|samesite|\berror page|custom error|\bhandler|file extension|"
                      r"\bisapi|\bcgi|\bdirectory browsing|autoindex|\bindexes\b|\bweb root|webroot|"
                      r"\bvirtual ?host|default (?:site|page|server)|\bquery string|url length|"
                      r"max_allowed_content|\bupload|\bbody size|client_max_body|\bhttp/2|\bwebdav|"
                      r"\bproxy_|\bmod_security|\bwaf\b|\bcors\b|\bjsonp|\brest interface"),
    ("filesystem", r"permission|\bowner(?:ship)?\b|\bchmod|\bchown|\bumask|mode (?:of|is|set)|"
                   r"\bworld[- ]writable|\bwritable|\bsticky bit|\bsuid|\bsgid|setuid|setgid|unowned|"
                   r"ungrouped|\bmount|partition|\bnodev|\bnosuid|\bnoexec|/tmp|/var|/home|/dev/shm|"
                   r"separate (?:partition|filesystem)|file system|filesystem|directory (?:is|are) "
                   r"(?:owned|restricted)|access to .*(?:director|files?) (?:is )?restricted|non-system "
                   r"partition|\bacls? on|\bntfs|shared folder|\bshares?\b|\bfile (?:is|are) "
                   r"(?:owned|restricted|protected)|config(?:uration)? file .*(?:owned|permission)|"
                   r"\bkubeconfig|\.conf (?:file )?(?:is )?owned|\bcron(?:tab)?\b.*(?:restricted|owned|"
                   r"permission)|\bat\b.*restricted|\bwebroot|web root|document ?root"),
    ("integrity", r"signed artifacts|verified packages|trusted base images|only trusted|signed\b|\baide\b|integrity|tamper|\bsecure ?boot|\bboot ?loader|\bgrub|bootloader|uefi|"
                  r"\btpm\b|signature (?:check|verif)|\bgpg|gpgcheck|repo_gpgcheck|package signing|"
                  r"content trust|signed image|image signing|\bnotary|checksum|hash of|immutable|"
                  r"read-?only (?:root|file ?system)|\bfile integrity|\bfim\b|code integrity|"
                  r"\bhvci|\bvbs\b|credential guard|lsa protection|runasppl|\bmeasured boot|"
                  r"configuration change|\barchive config|config(?:uration)? archiv|\bimage verif|"
                  r"software image|\bvib\b acceptance|acceptance level"),
    ("isolation", r"docker socket|mac policy|confined|permissive mode|enforce or complain|security context|page sharing|copy operations|single-function|dedicate the machine|unconfined|application pool|aufs|drag and drop|copy and paste|copy/paste|\bvm (?:isolation|tools)|isolation\.tools|\bvmci|shared memory|\bselinux|apparmor|\bmandatory access|\bseccomp|\bnamespace|userns|user namespace|"
                  r"\bprivileged\b|capabilit|\bcap_|net_raw|\bsys_admin|no-?new-?privileges|"
                  r"allowprivilegeescalation|privilege escalation|hostpid|hostipc|hostnetwork|host's "
                  r"(?:process|ipc|network)|\bcgroup|\bsandbox|\bdep\b|data execution prevention|\baslr|"
                  r"address space layout|randomize_va_space|ptrace|\bnx\b|exec-?shield|core dumps? "
                  r"(?:are|is) restricted|\bsuid_dumpable|kernel\.|\bsysctl|\bexploit protection|"
                  r"\bsehop|\bheap|\bcontrol flow|\bcfg\b|\bchroot|\bjail|isolat|\bpod security|"
                  r"\bsecuritycontext|readonlyrootfilesystem|run ?as (?:non-?root|root|user)|"
                  r"runasnonroot|\bcontainer user|\bmount propagation|\bdocker\.sock|\bdevice"),
    ("malware", r"file hash|real-?time protection|behavior monitoring|\bmaps\b|potentially unwanted|\bscan|zone information|autorun|autoplay|safedllsearchmode|protected mode|attack surface reduction|\basr\b|e-?mail scanning|script scanning|cloud-?delivered|tamper protection|malware|anti-?virus|antivirus|\bdefender|\bmalicious|\bvirus|\batp\b|advanced threat|"
                r"\bips\b|intrusion|\bav\b profile|antimalware|\bsmartscreen|\bwebfilter|web filter|"
                r"\bapplication control|\bapp ?control|applocker|\bsandbox(?:ing)? (?:inspection|scan)|"
                r"\bclamav|\bscan(?:ning)? (?:of )?(?:files|email|removable|downloads)|\bphishing|"
                r"\bransomware|\bbotnet|\bc&c|\bdns filter|\bzero-day|\bthreat"),
    ("patching", r"unsupported (?:windows|version|os|operating)|functional level|latest software|software package is installed|automatic|dnf-automatic|unattended-upgrades|version is|\bupdate|\bupgrade|\bpatch|up to date|up-to-date|latest (?:version|release|stable)|"
                 r"supported (?:version|release)|\bend of (?:life|support)|\beol\b|\bversion (?:is|of)|"
                 r"\bfirmware|\bhotfix|\bservice pack|\bcumulative|\bvulnerab|\bcve-\d|\bsecurity "
                 r"(?:fix|advisor)|\bpackage manager|repositor|\bwsus|\bauto(?:matic)? updates?"),
    ("availability", r"in use\b|keepalive|max\w*requests|max\w*clients|\bscope\b|log file size|\bstorage capacity|\blimits? (?:on|for|the number)|\bmax(?:imum)?[_ ]?(?:connection|session|request|startups|auth ?tries|"
                     r"clients|body|header|memory|cpu|pid)|\bquota|\brate[- ]?limit|eventratelimit|\bdos\b|"
                     r"denial of service|\bresource|\bmemory|\bcpu\b|\bpids?\b|\bulimit|\bkeepalive|"
                     r"\btimeout\b.*request|request ?timeout|\bbuffer|\bmaxstartups|\bhealth ?check|"
                     r"\brestart polic|\bhigh availability|\bredundan|\bfailover|\bdisk space|\bfull\b"),
]

_COMPILED = [(d, re.compile(p)) for d, p in _RULES]

# Sections of a benchmark that are about one kind of control, for titles that say too little (Windows
# user rights are named by the right alone: "Ensure 'Back up files and directories'").
_SECTION_HINTS: Dict[str, List[Tuple[str, Tuple[str, ...]]]] = {
    "windows": [(r"-1\.1\.", ("authentication",)), (r"-1\.2\.", ("authentication",)),
                (r"-2\.2\.", ("accounts",)), (r"-9\.", ("network_filtering",)), (r"-17\.", ("logging",))],
    "active_directory": [(r"-1\.1\.", ("authentication",)), (r"-1\.2\.", ("authentication",)),
                         (r"-2\.2\.", ("accounts",)), (r"-9\.", ("network_filtering",)),
                         (r"-17\.", ("logging",))],
}
_SECTION_COMPILED = {b: [(re.compile(p), ds) for p, ds in rules] for b, rules in _SECTION_HINTS.items()}


def classify(title: Optional[str], benchmark: Optional[str] = None, check_number: Optional[str] = None) -> List[str]:
    """The domains of a check, from its title, in DOMAINS order (empty when nothing matches: the check
    then only counts for requirements on secure configuration as a whole)."""
    text = (title or "").lower()
    found = {d for d, rx in _COMPILED if rx.search(text)}
    for rx, ds in _SECTION_COMPILED.get(benchmark or "", ()):
        if check_number and rx.search(check_number):
            found.update(ds)
    return [d for d in DOMAINS if d in found]


# Topics: narrower subjects a requirement can name when a whole domain is too wide ("lockout" rather than
# all of authentication). key -> (English name, pattern on the lower-cased title).
TOPICS: Dict[str, Tuple[str, str]] = {
    "lockout": ("Lockout after failed logons",
                r"lockout|lock ?out|faillock|pam_tally|failed log(?:i|o)n|login attempts|logon attempts|"
                r"retries|maxauthtries|deny=|unlock_time|unlock time|login failure"),
    "password_quality": ("Password length and complexity",
                         r"password creation|password (?:length|complexity|must meet|quality)|minimum password length|pwquality|"
                         r"minlen|minclass|complexity|[dulo]credit|password strength|password policy"),
    "password_history": ("Password reuse",
                         r"password history|reuse|remember|difok|enforce password history|previous passwords"),
    "password_age": ("Password age and expiry",
                     r"maximum password age|minimum password age|password expir|pass_max_days|pass_min_days|"
                     r"password age|max(?:imum)? age|expiration|password change"),
    "mfa": ("Multi-factor authentication", r"\bmfa\b|multi-?factor|two-?factor|2fa|smart ?card|\btotp"),
    "idle_session": ("Idle session timeout",
                     r"time-?out|times out|\bidle|inactivity|clientalive|\btmout\b|disconnect clients|"
                     r"session .*terminat|exec-timeout"),
    "screen_lock": ("Screen lock", r"screen ?saver|screen lock|lock screen|machine inactivity limit|lock-?delay|"
                                  r"idle-?delay|\bdevice lock"),
    "logon_banner": ("Logon notice",
                     r"banner|\bmotd\b|message of the day|/etc/issue|message (?:title|text)|logon message|"
                     r"legal notice|warning message|login message"),
    "privileged_access": ("Privileged accounts",
                          r"privileg|\badmin|\broot\b|\bsudo|su command|\buac\b|elevat|sysadmin|super_?priv|"
                          r"grant option|cluster-?admin|uid 0|\bwheel|\bdba\b|\bsa\b login|enable secret|"
                          r"domain admins|enterprise admins|schema admins|built-?in administrator"),
    "privileged_utilities": ("Privileged utilities",
                             r"su command|\bsudo|debug programs|ptrace|\bsetuid|\bsuid|xp_cmdshell|"
                             r"\bcron\b|\bat\b command|\bcrontab"),
    "inactive_accounts": ("Inactive and unused accounts",
                          r"inactive|unused accounts?|dormant|disabled accounts?|last logon|stale|\bguest"),
    "service_accounts": ("System and service accounts",
                         r"service account|system accounts?|interactive login|nologin|/etc/shells|"
                         r"shell (?:is|for)|machine account|managed service account|\bgmsa"),
    "audit_content": ("What audit records contain",
                      r"(?:are|is) collected|'audit |audit (?:policy|record|rule|events?)|captures|log ?format|"
                      r"logformat|log_format|log_line_prefix|\bdetail|success(?:ful)? and failure|"
                      r"'success'|'failure'"),
    "audit_protection": ("Protection of audit logs",
                         r"audit (?:log|configuration|tools?|rules?) .*(?:immutable|owned|mode|permission|group|"
                         r"protected)|log files? .*(?:owned|mode|permission|group)|(?:owned|mode|permission).*log|"
                         r"\bimmutable|audit tools|\b-e 2\b"),
    "central_logging": ("Logs sent to a central server",
                        r"remote (?:logging|logs\b|log server|server|host|syslog)|syslog server|logging (?:host|server)|log ?host|"
                        r"forward(?:ed|s)? (?:to|logs|journal)|journal-?remote|journal-?upload|send logs|"
                        r"\bsiem|\btrap|\blogging (?:source|trap)|remote logging"),
    "log_retention": ("Log retention",
                      r"retain|retention|max_log_file_action|keep_logs|not automatically deleted|\barchiv|"
                      r"rotate|logrotate|retention method"),
    "log_capacity": ("Log storage capacity",
                     r"log size|maximum log|space_left|max_log_file|disk_full|storage capacity|log file size|"
                     r"size limit|admin_space_left"),
    "file_integrity": ("File integrity monitoring",
                       r"\baide\b|file integrity|integrity (?:checking|monitoring|check)|tamper|\bfim\b|"
                       r"file hash"),
    "backup": ("Backup and recovery", r"backup|back up|point-in-time recovery|\brecovery|restore files"),
    "memory_protection": ("Memory protection",
                          r"\baslr|address space|randomize_va_space|\bdep\b|data execution|exec-?shield|\bnx\b|"
                          r"\bsehop|\bheap|control flow|\bcfg\b|exploit protection"),
    "segmentation": ("Network segmentation",
                     r"\bvlan|segment|\bdmz|\bzone\b|bridge|inter-?container|between containers|"
                     r"network ?polic|isolat|separate network|\bvswitch|port group"),
    "monitoring": ("Monitoring and alerting",
                   r"monitor|\balert|\btrap|\bsiem|send logs|remote logging|syslog server|log ?host|"
                   r"notification|\bnetflow|\bsflow"),
}

_TOPICS_COMPILED = {k: re.compile(p) for k, (_, p) in TOPICS.items()}


def topics(title: Optional[str]) -> List[str]:
    """The topics a check's title names."""
    text = (title or "").lower()
    return [k for k, rx in _TOPICS_COMPILED.items() if rx.search(text)]


def requirement_matches(mapping: dict, benchmark: str, check_number: str, check_domains: List[str],
                        check_topics: List[str]) -> bool:
    """Whether a check is evidence for a requirement whose mapping is
        {"all": bool, "domains": ["a", "b+c"], "topics": [...], "checks": ["linux:LNX-L1-5.3.2", "CIS-1.1.1"]}
    "b+c" asks for both domains; a check names a benchmark optionally."""
    if not mapping:
        return False
    if mapping.get("all"):
        return True
    for ref in mapping.get("checks") or ():
        bench, _, number = ref.rpartition(":")
        if number == check_number and (not bench or bench == benchmark):
            return True
    have = set(check_domains)
    for d in mapping.get("domains") or ():
        if all(part in have for part in d.split("+")):
            return True
    return any(t in check_topics for t in mapping.get("topics") or ())


def validate_mapping(mapping: dict) -> Optional[str]:
    """None when the mapping only names known domains and topics, else why not."""
    for d in mapping.get("domains") or ():
        for part in d.split("+"):
            if part not in DOMAINS:
                return f"Unknown domain: {part}"
    for t in mapping.get("topics") or ():
        if t not in TOPICS:
            return f"Unknown topic: {t}"
    for c in mapping.get("checks") or ():
        if not isinstance(c, str) or not 1 <= len(c) <= 100:
            return "A check is named by its number, optionally as benchmark:number"
    return None
