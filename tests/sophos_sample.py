"""
Sample configuration of a Sophos Firewall (SFOS 20.0, "fw01") as the XML
API's Get answers carry it, in the element names of Sophos's API reference
and its Python SDK. Built here, not captured from a device: no Sophos
Firewall is available to the test suite.

Typical state of a firewall set up in a hurry: web admin and the user portal
open on the WAN zone (SSH closed), an ACL exception allowing SSH from the
WAN, no login lockout, no password complexity, no disclaimer, no OTP,
patterns every 2 hours, one plain syslog server, an any-to-any rule left
enabled, an inbound rule without IPS, ATP on in log-only mode, an SNMP v2c
community, and no scheduled backup.
"""

API_VERSION = "2000.1"
USERNAME, PASSWORD = "ngcorion-api", "Fw-Api-Pass-1"


def zone(name, ztype, https, ssh, user_portal, ping="Enable", dns="Disable", snmp="Disable"):
    return f"""<Zone transactionid="">
  <Name>{name}</Name>
  <Type>{ztype}</Type>
  <Description />
  <ApplianceAccess>
    <AdminServices><HTTPS>{https}</HTTPS><SSH>{ssh}</SSH></AdminServices>
    <AuthenticationServices><ClientAuthentication>Disable</ClientAuthentication><CaptivePortal>Disable</CaptivePortal><RadiusSSO>Disable</RadiusSSO><ChromebookSSO>Disable</ChromebookSSO></AuthenticationServices>
    <NetworkServices><DNS>{dns}</DNS><Ping>{ping}</Ping></NetworkServices>
    <VPNServices><IPsec>Enable</IPsec><RED>Disable</RED><SSLVPN>Enable</SSLVPN><VPNPortal>Enable</VPNPortal></VPNServices>
    <OtherServices><WebProxy>Disable</WebProxy><WirelessProtection>Disable</WirelessProtection><UserPortal>{user_portal}</UserPortal><DynamicRouting>Disable</DynamicRouting><SMTPRelay>Disable</SMTPRelay><SNMP>{snmp}</SNMP></OtherServices>
  </ApplianceAccess>
</Zone>"""


def rule(name, action, log, src_zones=(), dst_zones=(), services=(), ips="None", status="Enable", position="Bottom"):
    def group(tag, child, values):
        if not values:
            return ""
        return f"<{tag}>" + "".join(f"<{child}>{v}</{child}>" for v in values) + f"</{tag}>"
    return f"""<FirewallRule transactionid="">
  <Name>{name}</Name>
  <Description />
  <IPFamily>IPv4</IPFamily>
  <Status>{status}</Status>
  <Position>{position}</Position>
  <PolicyType>Network</PolicyType>
  <NetworkPolicy>
    <Action>{action}</Action>
    <LogTraffic>{log}</LogTraffic>
    <SkipLocalDestined>Disable</SkipLocalDestined>
    {group("SourceZones", "Zone", src_zones)}
    {group("DestinationZones", "Zone", dst_zones)}
    <Schedule>All The Time</Schedule>
    {group("Services", "Service", services)}
    <WebFilter>None</WebFilter>
    <ScanVirus>Disable</ScanVirus>
    <ApplicationControl>None</ApplicationControl>
    <IntrusionPrevention>{ips}</IntrusionPrevention>
  </NetworkPolicy>
</FirewallRule>"""


ENTITIES = {
    "AdminSettings": ["""<AdminSettings transactionid="">
  <HostnameSettings><HostName>fw01.corp.example.com</HostName><HostNameDesc>Head office</HostNameDesc></HostnameSettings>
  <WebAdminSettings><Certificate>ApplianceCertificate</Certificate><HTTPSport>4444</HTTPSport><UserPortalHTTPSPort>443</UserPortalHTTPSPort><VPNPortalHTTPSPort>443</VPNPortalHTTPSPort><PortalRedirectMode>ip</PortalRedirectMode><PortalCustomHostname /></WebAdminSettings>
  <LoginSecurity><LogoutSession>30</LogoutSession><BlockLogin>Disable</BlockLogin><BlockLoginSettings><UnsucccessfulAttempt>3</UnsucccessfulAttempt><Duration>30</Duration><ForMinutes>1</ForMinutes></BlockLoginSettings></LoginSecurity>
  <PasswordComplexitySettings><PasswordComplexityCheck>Disable</PasswordComplexityCheck><PasswordComplexity><MinimumPasswordLength>Disable</MinimumPasswordLength><IncludeAlphabeticCharacters>Disable</IncludeAlphabeticCharacters><IncludeNumericCharacter>Disable</IncludeNumericCharacter><IncludeSpecialCharacter>Disable</IncludeSpecialCharacter><MinimumPasswordLengthValue>8</MinimumPasswordLengthValue></PasswordComplexity></PasswordComplexitySettings>
  <LoginDisclaimer>Disable</LoginDisclaimer>
</AdminSettings>"""],
    "Zone": [zone("LAN", "LAN", "Enable", "Enable", "Enable"), zone("WAN", "WAN", "Enable", "Disable", "Enable"),
             zone("DMZ", "DMZ", "Disable", "Disable", "Disable", ping="Disable")],
    "LocalServiceACL": ["""<LocalServiceACL transactionid="">
  <RuleName>Allow SSH from WAN (vendor)</RuleName>
  <Description>Temporary support access</Description>
  <IPFamily>IPv4</IPFamily>
  <SourceZone>WAN</SourceZone>
  <Services><Service>SSH</Service></Services>
  <Action>accept</Action>
</LocalServiceACL>"""],
    "OTPSettings": ["""<OTPSettings transactionid="">
  <otp>0</otp><allUsers>0</allUsers><otpUsers /><tokenAutoCreation>0</tokenAutoCreation>
  <otpUserPortal>0</otpUserPortal><otpSSLVPN>0</otpSSLVPN><otpWebAdmin>0</otpWebAdmin><otpIPsec>0</otpIPsec>
  <defaultTimeStep>30</defaultTimeStep><maxTimeStepsInterval>3</maxTimeStepsInterval><maxInitialTimeStepDiff>10</maxInitialTimeStepDiff>
</OTPSettings>"""],
    "User": [f"""<User transactionid=""><Username>{u}</Username><Name>{n}</Name><Password hashform="mode1">$sfos$7$0$abc{i}</Password><UserType>{t}</UserType><Profile>{p}</Profile><EmailList><EmailID>{u}@corp.example.com</EmailID></EmailList><Group>Open Group</Group><Status>Active</Status></User>"""
             for i, (u, n, t, p) in enumerate((("admin", "Super Administrator", "Administrator", "Administrator"),
                                                ("netops", "Network Operations", "Administrator", "Administrator"),
                                                ("jdoe", "John Doe", "User", "")))],
    "AdminAuthentication": ["""<AdminAuthentication transactionid=""><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></AuthenticationServerList></AdminAuthentication>"""],
    "Hotfix": ["""<Hotfix transactionid=""><AllowAutoInstallOfHotFixes>Enable</AllowAutoInstallOfHotFixes></Hotfix>"""],
    "PatternDownload": ["""<PatternDownload transactionid=""><AutoUpdate>On</AutoUpdate><Interval>Every 2 Hours</Interval></PatternDownload>"""],
    "SyslogServers": ["""<SyslogServers transactionid="">
  <Name>siem01</Name><ServerAddress>10.0.5.20</ServerAddress><Port>514</Port><EnableSecureConnection>Disable</EnableSecureConnection>
  <Facility>DAEMON</Facility><SeverityLevel>Information</SeverityLevel><Format>DeviceStandardFormat</Format>
</SyslogServers>"""],
    "Notification": ["""<Notification transactionid=""><MailServer>smtp.corp.example.com</MailServer><Port>587</Port><Authentication>Enable</Authentication><Username>fw-notify</Username><Password>Smtp-Secret-9</Password><ConnectionSecurity>STARTTLS</ConnectionSecurity><EmailAddress>fw01@corp.example.com</EmailAddress><SenderAddress>fw01@corp.example.com</SenderAddress><ManagementInterface>PortA</ManagementInterface><SendTo>netops@corp.example.com</SendTo></Notification>"""],
    "SNMPAgentConfiguration": ["""<SNMPAgentConfiguration transactionid=""><EnableAgent>Enable</EnableAgent><Name>fw01</Name><Description /><Location>Rack 3</Location><ContactPerson>netops</ContactPerson><AgentPort>161</AgentPort><ManagerPort>162</ManagerPort></SNMPAgentConfiguration>"""],
    "SNMPCommunity": ["""<SNMPCommunity transactionid=""><Name>monitoring</Name><CommunityString>public-ro-2019</CommunityString><Description /><AuthorizedHostIpv4>10.0.5.30</AuthorizedHostIpv4><AcceptQueries><V1>Disable</V1><V2c>Enable</V2c></AcceptQueries><SendTraps><V1>Disable</V1><V2c>Enable</V2c></SendTraps></SNMPCommunity>"""],
    "SNMPv3User": [],
    "FirewallRule": [
        rule("LAN to WAN", "Accept", "Disable", ["LAN"], ["WAN"], ips="lantowan_general", position="Top"),
        rule("Web server inbound", "Accept", "Enable", ["WAN"], ["DMZ"], ["HTTPS"]),
        rule("Any allow (temporary)", "Accept", "Disable"),
        rule("Old VPN rule", "Accept", "Disable", ["VPN"], ["LAN"], status="Disable"),
        rule("Drop all", "Drop", "Enable"),
    ],
    "ATP": ["""<ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><Policy>Log Only</Policy><InspectContent>untrusted</InspectContent></ATP>"""],
    "BackupRestore": ["""<BackupRestore transactionid=""><ScheduleBackup><BackupMode>Local</BackupMode><BackupPrefix>fw01</BackupPrefix><FTPServer /><Username /><FtpPath /><EmailAddress /><BackupFrequency>Never</BackupFrequency><Day /><Hour>0</Hour><Minute>0</Minute><Date /></ScheduleBackup></BackupRestore>"""],
    "Time": ["""<Time transactionid=""><TimeZone>Asia/Tehran</TimeZone><SyncwithNTPServer>Enable</SyncwithNTPServer><PredefinedNTPServer>Enable</PredefinedNTPServer></Time>"""],
}
