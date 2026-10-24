# Changelog

## 2.1.1 — 2026-10-24

### Fixes

- Full review of every page (desktop and phone width, each tab, every
  New/Add dialog) and of every API call the web UI makes against the
  backend's routes, methods and query limits. Found and fixed:
  - Asset 360 showed the zone of the last risk score, not the asset's;
    scores left on an old zone (e.g. by the zone-list migration) are
    recalculated once at startup (risk/zone_rescore.py), so "Recalculate
    all" is no longer needed after upgrading.
  - Unknown devices and Topology neighbours offered the first asset type
    when none is drawn as the device (a camera became a Firewall); the type
    is chosen by hand then.
  - Untranslated text: "e.g." placeholders of the asset, owner, OS, port,
    location, discovery and CVE forms; the audit result's status and risk
    levels; the notification channels' cards and the send log's subject,
    status and error; port state tooltips; four page names on the
    no-access page.
  - A React key passed inside spread props (Risk, Hardening impact).
  - An SNMP credential that no longer decrypts (SECRET_KEY changed) wrote
    a traceback on every poll for every host; it is one warning per host.
- New Backup: the asset list was empty (it asked the asset API for 500 per
  page, over its limit of 100) and the device type stayed on Cisco whatever
  the asset. GET /api/backups/devices lists every asset with the family a
  backup of it is taken as (told from its type, vendor and system, else its
  last backup); choosing an asset sets the device type, which can still be
  changed. A backup without a type is taken as the detected family; a type
  no backup driver has is refused with a clear message. The New Backup and
  backup view dialogs had no panel or button styles unless Auto Discovery
  had been opened first; they bring their own now, and the view shows the
  device and source by name.
- Architecture Validation checks the topology against Cisco SAFE, and only
  the topology. Most of its checks were about the inventory, backups and
  audits (no IP, no owner, never audited ...), which other modules cover.
  - Rules (rules/safe.yaml, AV-101 to AV-141), by SAFE domain:
    segmentation (an unfiltered path - over active links, past no firewall -
    from the Internet, the DMZ, the guest network, users or a lab to hosts of
    more trusted places; servers and user devices in the wrong place),
    management (the management network reachable without a firewall),
    threat defense at the edge (one edge firewall), availability (one
    Internet connection, single points of failure with the assets they cut
    off, servers and critical assets on one device, single uplinks, links
    down or no longer reported over LLDP/CDP) and visibility (devices not
    in the topology, places unknown).
  - Each asset's place in the network comes from its zone: Network Zones
    has a "Place in the network (Cisco SAFE)" choice, read from the zone's
    name when not chosen ("DMZ" is the Edge, "Internal Server Zone" the Data
    Center).
  - A finding shows what the topology shows: the path, the only link, the
    assets cut off. The page groups findings by check, counts open ones per
    SAFE domain, and lists every check under "What is checked". The report
    has the evidence too.
  - Migration f5a7c9e1b3d4 adds architecture_findings.evidence and
    risk_zones.place, and removes the findings of the retired checks;
    Remediation closes their items as "Architecture Validation no longer
    makes this check", not as fixed.
- Asset icons no longer read the asset's zone as a keyword (a server in
  "Internet / Public" was drawn as an Internet link).
- One list of network zones. Asset List's zones (network_zones) and the
  zones Risk scores (risk_zones) were two lists: a zone set on an asset in
  Asset List ("Data Center", a new "Edge") counted in Risk only when a risk
  zone had the same name, and never in risk filters, asset groups, alert
  rules, report scope or the dashboards, which read the risk profile; a
  zone set in Risk did not show in Asset List.
  - Asset Requirements, Network Zones manages the zones Risk scores, with
    an exposure score (0-100); a change recalculates the zone's assets, a
    zone with assets cannot be deleted. The Excel zones sheet has a Score
    column; the assets' Overview sheet calls the column "Network Zone"
    (the old "Role" header still imports) and refuses a name that is not a
    zone.
  - An asset's zone is the same wherever it is set (asset form, Excel,
    Risk, bulk actions) or read (app/models/asset_zone.py); setting it in
    Asset List recalculates the asset's risk.
  - Migration e3b5d7f9a1c2 moves every Asset List zone into the one list
    ("Internal" is "Internal Server Zone", "External" is "Internet /
    Public"; a new one gets the no-zone score), gives each asset one zone
    (the one changed last where the two disagreed) and drops network_zones.
    Recalculate all risk scores once after upgrading.
- Editing an asset set its last audit date to the day of the edit; the
  date moves only with an audit now.
- Dependencies with published advisories: Pillow 13.0.0 (through
  WeasyPrint), brotli 1.2.1, certifi 2026.10.23, opentelemetry-api 1.45.1;
  frontend follow-redirects, undici, vite, zod and vitest 4.1.12.
- Addresses of a host besides its inventory IP: a FortiGate may be managed
  on one address and answer SNMP or send syslog on another.
  - SNMP: "SNMP address" in the host's SNMP credential (an IP address or a
    host name); polling, LLDP/topology and endpoint discovery use it,
    the asset's IP address when empty.
  - Syslog: an asset has "Other addresses" (Network & System edit; table
    asset_addresses, migration d9f1b3c5e7a8), and syslog from any of them
    is the asset's. Under Syslog, Sources, an address outside the
    inventory can be assigned to the asset it is. An address belongs to
    one asset and is never another asset's IP; each change is in the
    audit trail.
- Asset edit dialogs: a taller form ran under its buttons; it scrolls
  inside now.
- Monitoring storage: how long SNMP metrics are kept (raw, 5-minute,
  hourly, daily) and their disk space were only settable in .env. A
  system administrator sets them under NOC hosts, "Storage" (System
  Configuration section noc_metrics_storage, .env as defaults; changes in
  the audit trail). The panel shows what syslog messages and SNMP metrics
  take against their limits and the disk's free space, and warns when the
  limits allow more than is free; the syslog settings show the space the
  messages take.
- Syslog and NOC metrics storage budgets: the check measured the tables'
  files, which do not shrink when rows are deleted. Once a table had
  reached its budget, every run deleted again - a fifth of the syslog
  messages, up to a million metric rows - until little history was left.
  Both now measure the space the stored rows take (their count and
  average size, with their share of indexes) and delete only the excess,
  oldest first. app/core/table_usage.py.
- Assets: physical and virtual servers could not be told apart. An asset
  type is now physical or virtual ("Runs as"; migration c7e9a1b3d5f6 marks
  types named VM or Virtual ... virtual). An asset of a virtual type must
  name the physical server it runs on: the Add and Location forms say so,
  offer only physical assets, and the API refuses a virtual host. The
  asset types sheet of the Excel file has a "Virtual" column (Yes/No; a
  file without it leaves the types as they are).
- Assets: an asset could not be saved without a serial number, a value or
  the last audit and patch dates. The edit forms sent an empty field as
  "", which the API refused for a date or a number (422) and stored for
  the serial - unique, so the next asset without one failed (500). An
  empty field is now "not set" in the API, the forms and the model, and
  migration b5d7f9a1c3e4 clears stored "" serials. The serial number no
  longer counts toward a complete asset.
- Assets: the last audit date was only ever typed in, and there was no
  last hardening date. Both are kept by NGCorion now: the last audit date
  when an audit of the asset completes, the new last hardening date when a
  hardening change on it succeeds (any family); the migration fills both
  from what already ran. The Add asset form no longer asks for the last
  audit date; the Security & Audit tab shows the last hardening.
- Risk detail, Audit Findings: "Hardening Status" and "Verification
  Status" were always "-" - the table read the audit results, which carry
  no hardening. It now reads GET /api/risk/assets/{id}/findings (risk read,
  like the page): the controls that failed in the audit the score reads,
  failing still or fixed since, with the hardening status (not hardened,
  previewed only, running, applied, failed - the error on hover), the
  verification status (verified, holds and awaiting re-audit, not verified,
  check still fails), the state now, a risk acceptance, and the time of the
  last change. The actual value is configuration from the device: it is
  returned only to who may read that audit (Auditing read, its owner or an
  admin), as before.
- Risk detail, Hardening Impact: the card showed only the number of
  fixed findings, "before" values that were always empty, and a note to
  developers. It now compares, since the audit the score reads, the failed
  controls and the audit risk just after that audit with now, and the risk
  score just before the first change with now, each with its change; says
  how many changes ran (verified, failed) and how many fixed controls still
  count until a re-audit (Cisco, FortiGate); and without a change since the
  audit offers hardening.
- Risk and hardening overview after hardening Linux (and Windows, SQL
  Server, Apache, MongoDB and the benchmark modules): the risk page said
  nothing was fixed by hardening. These services set a fixed finding to
  PASS but wrote no hardening record - only Cisco and FortiGate did - so
  "Fixed by hardening", the hardening factor and the hardening overview
  never saw them; and the risk score counted "fixed by hardening" only
  among findings still failing. Every fix that runs is now recorded
  (commands and output with secret parameters redacted, verified or
  not), and a verified fix counts whether the finding still fails until a
  re-audit or already passes. Fixes run before this version have no
  record; hardening them again or a re-audit brings the pages up to date.
- Advisories update (OSV.dev): "OSV answered HTTP 403 for Ubuntu" said
  nothing about what to do. The bucket is public, so a 403 is about where
  the request comes from: Google, which hosts it, refuses addresses in some
  countries. The message now says so and names the ways around it - a
  proxy (HTTPS_PROXY) or a mirror (OSV_BASE_URL) in .env, or all.zip
  downloaded on another network and imported. Both settings are now in
  .env.example, and a job's error ends its sentence before "The database
  was not changed.".
- Linux over SSH on systemd 257 and later (Ubuntu 25.04+, Debian 13,
  Fedora 42+): every command failed with "Pattern not detected" - the
  software collection, Linux and Apache audits, hardening and the MongoDB
  audit alike. These systems' /etc/profile.d/80-systemd-osc-context.sh
  wraps every prompt in OSC 3008 terminal sequences with a new ID each
  time; netmiko took them for part of the prompt, which then never matched
  again. OSC sequences (also OSC 7 and OSC 133 from terminal
  integrations) are now dropped from everything read, and the prompt is
  read again when they had got into it (app/core/ssh_terminal.py).
- CVE update: the online update (and a package import) failed at "review
  and apply" with "Unexpected error: DataError" when NVD sent a description
  with a NUL character, which PostgreSQL refuses in text, or a CPE
  criterion longer than its column (CPE 2.3 sets no length; NVD has long
  firmware versions and product names). NUL characters are dropped, the
  CPE columns are unbounded text (migration a3c5e7f9b1d2), and short labels
  (status, severity, KEV ransomware) are cut to their width. A failed job
  now names the database's reason, e.g. "DataError (value too long ...)".
- Schedule discovery: saving a new scheduled discovery turned the page
  white and saved nothing. The form sent the empty group-audit fields
  ("" for a group and a credential profile), which the API refused as not
  numbers, and the page then rendered the API's list of errors, which
  crashed it. A discovery sends no audit fields now, and the scheduling
  pages show a refusal as text naming the field.
- Software, "Collect now": every failure said "Could not connect to the
  asset". A Windows password WinRM refused now says the username or
  password was not accepted; WinRM not answering says why (connection
  refused - WinRM not enabled on the port or a firewall -, no answer in
  time, HTTPS certificate not accepted, address not resolved); a failure
  after signing in says the connection worked and gives the reason. The
  server log records the whole error, and the audit trail the reason.
  The SSH connection errors are translated into Persian.
- Software, "Collect now", when the server sends no message of its own:
  the form said only "Could not collect the software list". It now says
  which case it is: the page stopped waiting (the collection may still
  finish), the server could not be reached, or the server answered with
  an error code and no message (a 500 from NGCorion, or a 502/504 from
  the proxy). A database error during a collection no longer turns into
  such a bare 500: the audit trail entry is written on a fresh
  transaction and the reason is returned.
- Every page shows a refused request's own message: the sixteen Redux
  slices that kept the API's error as it came (a FastAPI 422 list, or an
  {error_type, message} object) now keep text, e.g. "name: Field
  required". Before, requirements, NOC hosts, topology, architecture
  validation and design suggestion crashed on such an answer, and the
  others showed nothing.
- A page that crashes while rendering now shows "This page ran into a
  problem" with "Reload page" and "Go back" inside the layout, instead of
  a white window; moving to another page clears it.

### Dashboard

- The dashboard is rebuilt around what to do next, in five rows: the
  security risk score with its six parts (each opens its module) and the
  30-day change of the average asset risk; "Needs action" - assets with
  exploited (KEV) vulnerabilities, critical alerts nobody acknowledged,
  monitored devices not answering, overdue remediation, expired or expiring
  certificates, unsupported software, configuration changed outside NGCorion
  this week, failed scheduled jobs, a failed backup of NGCorion and requests
  waiting for your approval, only those above zero, each opening the
  filtered list; coverage (audited, backed up, monitored); 90-day trends of
  risk and compliance; and the ten riskiest assets with the factor that adds
  most to each score.
- Each part comes from the modules the user may read, so an account with
  only some modules still gets a dashboard of those.
- The asset count is now the whole inventory (it counted only assets with a
  risk score). The module tiles, "Compliance vs Hardening" and the second
  risky-assets table are gone.
- The trends take every asset's latest value at each point, so an asset
  audited ten times counts once.
- Alerts can be filtered to critical ones ("Critical only", or
  `?severity=critical`), and Remediation opens a view from the address
  (`?view=overdue`).
- New endpoint `GET /api/dashboard/overview`.

### Assets overview

- Rebuilt around the state of the inventory: assets added in the last 7
  and 30 days, license use and unknown devices NOC saw on the network;
  missing details (no owner, IP address, operating system, location, or a
  risk zone never chosen); coverage by audits, configuration backups, SNMP
  monitoring and end-of-life data; the mix by type, vendor, operating
  system, status and zone; and the assets added last.
- Every figure, card and bar opens the asset list filtered to what it
  counts. The asset list reads its filters from the address
  (`?missing=owner|ip|os|location`, `?type=`, `?vendor=`, `?os=`,
  `?status=`, `?added=<days>`) and shows each as a chip that removes it.
- New endpoint `GET /api/dashboard/assets` (asset list read access; the
  coverage of other modules and the unknown devices need their own).

### Risk overview

- Rebuilt around what builds the risk and where it sits: assets per level,
  the average score, incomplete scores and assets with exploited
  vulnerabilities; the average points each of the seven factors adds to
  the scores and its share, each factor opening the page where it is
  fixed; assets per zone and level; 90 days of the average score and of
  the critical and high assets (from each asset's latest score at every
  point); why scores are incomplete, with the action that fixes each; and
  the ten riskiest assets with their main factor. The confidentiality and
  level donuts and the monthly bar trend are gone.
- Risk of assets reads `?level=`, `?zone=` and `?incomplete=1` from the
  address, which every figure and matrix cell uses, and shows each as a
  chip that removes it.
- New endpoint `GET /api/dashboard/risk` (risk read access).

### Hardening overview

- Rebuilt in five parts, counting only changes that ran (previews left
  out): figures (success rate - "Hardening Score" was this, under a
  misleading name -, changes made - "Applied Policies" counted actions -,
  changes in the last 30 days, assets hardened and never hardened, failures
  not made good since, pending); needs attention (failed changes with the
  device's error, a link to the backups taken before the change and "Try
  again"; changes not verified or whose control still fails; assets hardened
  since their last audit); controls still failing in each asset's latest
  audit with no fix, with links to their remediation items and to hardening;
  the impact (findings fixed, and the average risk of assets hardened in the
  last 90 days before their first change and now); and the reach (by asset
  type and benchmark level, latest changes). The duplicate "Automation
  Success Rate" card is gone.
- Missing controls are taken from each asset's latest audit only (an old
  audit's failures counted before).
- Run hardening opens a wizard from the address
  (`?mode=fix-unsuccessful`, `?mode=fix-all`), and Remediation starts with
  a search (`?q=`).
- New endpoint `GET /api/dashboard/hardening` (hardening read access).

### In-app help

- A help button ("?" in the header, or the "?" key) on every page opens that
  page's help beside it: a summary, then foldable sections - main tasks step
  by step, an example with real values, what the statuses mean, who may do
  what, what to take care of, common problems and links to related pages -
  with a search inside the help. Every menu page has it, in Persian and in
  English; it ships with the product and works offline.
- The sidebar opens one group at a time: opening a group closes the one that
  was open, and going to a page (from the menu, the search, an alert's link
  or Back) opens that page's group. The group of the current page can be
  closed too.
- The global search finds help sections too and opens the page with its help
  at that section (`?help=<section>` in the address, so it can be shared).
- Header and phone-width fixes: the license badge no longer clips beside the
  search box, the header steps down below 1280px instead of overlapping, four
  pages no longer scroll sideways on a phone, and "Clear history" on Run
  audits no longer covers "New audit".

### API keys

- New tab Administration → Users → API keys (system administrators): keys
  other systems (SIEM, CMDB, scripts) call the API with, as
  `Authorization: Bearer ngk_…`. The token is shown once; only the SHA-256 of
  its secret is stored.
- Each key acts as its own service account whose permissions are the key's
  access (read, or read and write, per module), so every permission and
  ownership rule applies and everything it does is in the audit trail under
  that account. A key never gets user management or credential profiles,
  only reads hardening, device backups, system settings and logs, never
  deletes and is never an administrator.
- Every key has an end date (90 days by default, 365 at most) and can be
  limited to some addresses; renewing replaces the secret at once, revoking
  is final. New alert event "API key expires soon".
- Service accounts are kept out of the user list, alert and report
  recipients and owner pickers, cannot sign in with a password and cannot
  be edited from the users page.

### Global search

- A search box in the header of every page ("/" or Ctrl+K): assets by name,
  host name, address, MAC in any notation, serial number, model or OS; CVE
  ids; unknown devices on the network; remediation findings; TLS services;
  software; asset groups; users; reports; and the menu's own pages. Arrow keys
  and Enter open a result; Persian digits are understood.
- Each kind of result appears only for users who may read its module, and
  reports only among those the archive shows them.
- The CVE page opens a CVE from `?cve=`; the software, asset group, report
  archive and user pages take their search from `?q=`.

### TLS certificates

- New tab Security assessment → Vulnerabilities (CVE) → TLS certificates: the
  certificate every TLS service of the assets presents (web, device
  management, LDAPS, mail …), read with a plain TLS handshake on the usual TLS
  ports and on the open ports discovery saw with a TLS service; no credentials,
  nothing changes on the device. Automatic every 24 hours, or on request.
- Each certificate is checked for expiry (expired; expiring within 30 days by
  default), trust (self-signed or an unknown issuer; the organisation's own
  CAs can be trusted), the asset's host name, weak keys (RSA under 2048 bits)
  and signatures (SHA-1, MD5), and whether the service still accepts TLS 1.0
  or 1.1.
- Services can be added by hand (another port, or a site with its own name
  sent in the handshake) and turned off when they are not the organisation's.
- Problems open remediation findings (source "TLS certificates": expired high,
  untrusted / weak / old protocol medium, another name low) that close by
  themselves after the fix, raise the vulnerability factor of the risk score,
  and have two alert events (certificate expired, expiring soon). The asset
  page lists its services; new report "TLS certificates" (PDF and Excel).
- Remediation titles on the asset page are now translated like on the
  remediation page.

### End of life

- New tab Assets → Software → End of life: until when the vendor still ships
  security fixes for the operating system, firmware and server software of
  every asset, from endoflife.date (24 products, among them Ubuntu, Debian,
  RHEL and its rebuilds, SUSE, Windows Server, Windows, FortiOS, Cisco IOS XE,
  VMware ESXi, SQL Server, PostgreSQL, MySQL, MongoDB, Apache, nginx,
  Kubernetes and Docker Engine). Status per component and asset: unsupported,
  paid extended support only, ending within the warning period (180 days by
  default), supported, not in the catalog.
- The catalog ships with NGCorion and works offline; an administrator updates
  it from endoflife.date, imports a file (another NGCorion's export or a saved
  endoflife.date answer) on a closed network, and adds products of their own
  for what endoflife.date does not track. A date can also be entered by hand
  for a device that has no software inventory.
- Unsupported software opens remediation findings (source "End of life": high,
  or medium with paid extended support only) that close by themselves after
  the upgrade, raises the vulnerability factor of the risk score, and has two
  alert events (past the end of support, support ending soon). The asset page
  shows the vendor support of its components; new report "End of life" (PDF
  and Excel).
- Dates inside alert details and other sentences from the server now read in
  the UI's calendar (Persian dates in Persian).

### Production image start

- The image compiled with Cython failed to start (a plain method on a request
  model of the compliance module); fixed, and a test now keeps request models
  free of plain methods.

### Compliance with standards

- New page Remediation & hardening → Compliance with standards: how far the
  latest audits meet PCI DSS 4.0, ISO/IEC 27001:2022 and NIST SP 800-53 Rev. 5,
  for every asset or one asset group, with a score per standard and per
  requirement, coverage, and the gaps (failing checks, the most urgent first,
  with the assets that fail them).
- Every check of the 17 audit modules is put in security domains from its
  title (about 94% of the 2,044 checks land in at least one); a requirement is
  evidenced by the checks of its domains, of narrower topics (e.g. lockout after
  failed logons) or by check number. An administrator can correct the domains
  of a check. Results the benchmark policy makes optional or excludes do not
  count.
- Requirements no check covers are assessed by hand (met, partly met, not met,
  with a note and a validity date); a requirement with audit evidence can only
  be marked not applicable by hand.
- The organisation's own standards (e.g. national requirements): create and
  edit them requirement by requirement, or import a definition file; any
  standard can be exported in the same format and turned off.
- New report "Compliance with a standard" (PDF and Excel): overview by section,
  every requirement, gaps, what is assessed by hand, and every failed check of
  every asset.
- The benchmark policy's Benchmarks tab now counts each asset's latest audit of
  every benchmark (an asset audited as a Linux server and a Docker host counts
  in both).

### Benchmark policy

- New page Remediation & hardening → Benchmark policy: the organisation's
  decisions on the audit benchmarks. A rule names a benchmark and one check
  (shown with whether it fails in the latest audits now) or a whole level
  (e.g. L2), for every asset or one asset group, with a reason and an optional
  end date, and decides the check is **optional** (recommended, out of the
  compliance score and remediation, still in the risk score) or **excluded**
  (not applicable: out of the score, remediation and the risk score).
- Four eyes: a rule applies once someone other than the requester approves
  it. Managers and administrators decide; a whole level, or excluding a high or
  critical check, needs an administrator. Requests can be withdrawn, rules in
  force ended, and rules with an end date expire on their own. Every step is in
  the audit trail (`audit_policy.request/approve/reject/end`).
- Audits are scored under the rules in force: approving or ending a rule
  rescores that benchmark's audits at once, and new audits are scored by the
  `audit-policy` background task. The module's own score is kept
  (`audit_sessions.raw_compliance_pct`), and the Benchmarks tab compares the
  two. Remediation items for checks the policy no longer requires close with
  the reason "by policy".

### Unknown devices on the network

- New page Network & monitoring → Unknown devices: the addresses the monitored
  routers and switches see that are not in the inventory. NGCorion scans
  nothing; it reads their ARP table (IP ↔ MAC, IP-MIB, with the newer
  ipNetToPhysicalTable as fallback) and MAC table (which MAC behind which port,
  Q-BRIDGE-MIB, with BRIDGE-MIB as fallback) over SNMP, by default every
  15 minutes, with the SNMP credentials already given in NOC → Hosts.
- Each address shows the maker (from the MAC prefix, nmap's list), a guess of
  the kind with its icon (camera, IP phone, UPS, PLC, virtual machine,
  computer, network device …), the device, port and VLAN it was seen on (the
  access port when it shows on several), and when it was first and last seen.
  Random (private) MACs of phones and laptops are marked.
- Add as asset (IP, MAC and maker filled in, the asset type matching the guess
  chosen; counts against the license like any asset), or ignore one or many
  with a note. Tabs for new (24 hours), ignored, known, the devices read and
  their errors, and the settings (system administrators). The NOC dashboard
  shows the count.
- Alert "New device on the network" when an address that is not an asset first
  appears; what the first read of each device finds is the baseline and raises
  nothing, and more than 10 at once make one alert.
- Rows no longer seen are forgotten: private MACs after 7 days, unknown after
  30, known after 90, ignored after 365.

### Topology from LLDP and CDP

- NOC reads the LLDP (LLDP-MIB) and CDP (CISCO-CDP-MIB) neighbour tables of the
  monitored devices, by default every 60 minutes, and draws the Topology map
  from them: a cable reported from both ends makes one link, with the ports as
  the devices name them and the speed of the port. A link drawn by hand for the
  same ports is confirmed, never changed or doubled.
- Neighbours are matched with the inventory by the chassis id the neighbour
  reports, its MAC or management address, or its name. New view Topology →
  Neighbours (LLDP/CDP): on the map, not on the map, not in the inventory,
  removed from the map, the devices read, settings. A neighbour that is not an
  asset (access point, IP phone, server) can be added as one, its link drawn at
  once.
- A found link the devices stop reporting turns red and dashed and raises the
  new "Network link lost" alert; it is removed after 30 days. A found link
  removed from the map stays off it until "Add to map".
- The link panel shows where a link comes from and when it was last reported;
  the map counts found and missing links. Interface names on links can be up to
  100 characters.

### Unknown devices behind Cisco IOS switches, every VLAN

- A Cisco IOS switch keeps one MAC table per VLAN and only VLAN 1's answered
  before. NGCorion now reads the VLAN list (CISCO-VTP-MIB) and each VLAN's table
  (community@VLAN on SNMP v2c, context vlan-<id> on v3, up to 64 VLANs), so the
  devices of every VLAN are found with their switch port and VLAN.
- The Unknown devices search also matches the name of the device an address
  was seen on.

### Real ports on the Topology map

- A device polled by NOC is drawn with its own physical ports (IF-MIB, up to
  96) instead of the generic port list of its type, so a link drawn by hand or
  found over LLDP/CDP sits on the exact port; long and short port names
  (GigabitEthernet1/0/24, Gi1/0/24) are the same port.

### Persian sentences with English names

- In alerts, the audit trail, the asset page timeline and group runs, the
  device, port, user and product names inside a Persian sentence stay whole and
  in place (they used to be moved around by the right-to-left layout), a
  one-word name such as `dist-switch-02` no longer breaks at its hyphen, and a
  Persian sentence that starts with an English word (MAC, SNMP) reads right to
  left.

### Nine new device icons

- Camera, NVR, laptop, IP phone, UPS, PLC / industrial, WAF, IPS and VPN, with
  name and maker rules (e.g. Hikvision → camera, Yealink → IP phone, APC →
  UPS, Imperva → WAF). Icons chosen by hand stay; an asset whose icon is
  automatic may now show one of the new ones.

## 2.1.0 — 2026-10-17

### Licensing by number of assets

- A license covers a number of assets: the plan (Essential 25, Professional
  100, Business 250, Enterprise 500 / 1,000 / 2,500, Enterprise Unlimited)
  plus add-on packs of 50 assets. Audits and hardening runs are no longer
  counted; the audit/hardening quotas and the license server's `/consume`
  are gone.
- Every asset in the inventory counts. Adding an asset beyond the limit (by
  hand, by Excel import, from discovery) is refused with a clear message; an
  import or a bulk approval adds what fits and reports the rest.
- While the inventory is larger than the license covers, audits and hardening
  run only on the first assets the license covers (the oldest); the others
  stay in the inventory, marked "Outside license". Scheduled audits follow the
  same rule (before, they were not licensed at all), and so does the Cisco
  auto-audit.
- Without contact with the license server: the license's plan for 48 hours,
  then a pilot license (5 assets) for up to 30 days, then locked. The plan
  returns with the next answer from the license server; nothing changes on the
  license itself. Before, the license server overwrote the plan with the pilot
  plan for good. `LICENSE_OFFLINE_GRACE_HOURS` is no longer read.
- The License page shows the plan, assets used against the limit, add-on
  packs, expiry, the last contact with the license server, and the offline
  pilot; the asset pages show the same in the header. The heartbeat reports
  the asset count to the license server.
- Activating a license sends a heartbeat at once, so the license server sees
  the asset count from the moment of activation, not up to an hour later.

### Offline (air-gapped) licenses

- For a server without internet access: on the first-run screen or the
  License page, download a request file, have the license administrator sign
  it (license server admin console: the license must be marked offline), and
  upload the license file you get back. It is bound to this server and valid
  one year (never past the license's expiry); NGCorion then runs without any
  contact with the license server. Renewal is the same two-file exchange; the
  License page warns 30 days before the file ends.
- A file cannot be edited, forged or used on another server. A clock set back
  (before the file's issue time, or below the last time seen, also across a
  restart) invalidates the license.

### Licensing can no longer be bypassed by configuration

- Every answer of the license server is signed (Ed25519). NGCorion accepts an
  answer only if it verifies against a key built into the code, is about this
  license and this machine, and echoes the request's nonce. A stand-in server
  that answers "valid" no longer unlocks anything.
- The machine fingerprint is computed on the licensed machine (hardware/VM
  UUID and the host's machine-id). Before, it came from the license server
  itself, so every installation had the same fingerprint and one license could
  run on any number of servers.
- The offline cache stores the signed token and is verified again on restart;
  the 48h grace window counts from the signed issue time, and a clock set
  back invalidates the license.
- The license server's address is fixed: `https://lic.ngcorion.com`, part of
  the code next to its signing key, verified against the public certificate
  authorities. `LICENSE_SERVER_URL` and `LICENSE_SERVER_CA_BUNDLE` are no
  longer read (a leftover value only logs a warning).

### Release images carry the code

- The backend image contains all code and the built frontend; the checkout is
  no longer mounted into the container (`./app`, `front/dist`, `pyproject.toml`,
  `uv.lock`). Inside the image the code is root-owned and read-only for the
  application user. Development with live code: `docker-compose.dev.yml`.
- A `.dockerignore` keeps `.env`, TLS keys under `traefik/certs`, the git
  history, tests and local environments out of the image. Before, the whole
  checkout was copied in, including `.env`.
- Slow first starts: Postgres gets 5 minutes to create its database and
  the backend 10 minutes to apply every migration before their health checks
  count, and uvicorn waits 2 minutes for a starting worker (it killed every
  worker after 5 seconds on a slow VM, in a loop).
- The installation's `.env` (SECRET_KEY, SMTP, ...) is handed to the backend
  as environment variables (`env_file` in docker-compose.yml); the app used to
  find it only because it had been copied into the image.
- `deploy.sh` no longer needs Node.js on the host; it builds
  `ngcorion/backend:<version>` and keeps the previous image for rollback.
- Base images and the Python package index are build arguments
  (`BASE_REGISTRY`, `PYPI_INDEX`, `NPM_REGISTRY`); the defaults stay the
  Iranian mirrors. CI builds the image and checks it starts, answers and
  contains nothing it should not.

### Security (AFTA review)

- Idle sessions end: a session unused for `SESSION_IDLE_TIMEOUT_MINUTES` (30)
  is ended at the server and its token revoked; the UI signs out after the
  same time without keyboard or mouse input (its automatic refreshes would
  otherwise keep a session alive on an unattended screen). New table
  `user_sessions`.
- A notice on the login page before sign-in (`LOGIN_BANNER`, or the built-in
  Persian/English one).
- The audit trail (`audit_logs`) is append-only in the database too: a
  trigger refuses changes and deletions (the backup/restore engine, which
  replaces the whole database, is the one exception).
- The sign-in history (`login_logs`) can no longer be cleared from the Logs
  page: it is an authentication record, and clearing it also reset the
  failed-login counter an attacker is held back by.
- System Configuration → Pinned device keys (administrators): the SSH host
  keys and HTTPS certificates NGCorion pinned, with the asset each belongs to,
  and *Remove pin* for a device that was reinstalled. Before, a device that
  changed its key could not be audited again on the appliance (no shell to run
  `ssh-keygen -R`). Each removal is audited with the dropped fingerprint.
- Audit trail page (System → Audit trail, Logs read permission): the whole
  security audit trail (`audit_logs`) and every sign-in attempt
  (`login_logs`), with text search, filters (module, action, result, user,
  address, date range) and paging done on the server, and CSV export of what
  the filters select. Exports are formula-safe and recorded in the trail
  (`audit_trail.export`). Before, the Logs page showed only the latest 50
  entries of each section, with no search.
- A system administrator can set a temporary password for another user who
  cannot sign in and has no email for the self-service reset (User
  Management → key button; `POST /api/users/{id}/reset-password`). The
  password meets the password policy (the dialog can generate one), the
  user's open sessions end at once, the user must choose their own password
  at the next sign-in, and the action is in the audit trail
  (`user.password_reset`, never the password). Changing a password through
  Edit user still needs the user's current password (5f147c8); before, the
  only way back for such a user was to delete and recreate the account.
- Date fields follow the interface language: in Persian every date field
  (audit trail, reports, remediation deadlines and acceptances, asset dates,
  CVE export, NOC time range, the system clock) takes and shows Jalali dates
  with Persian digits, typed (`۱۴۰۵/۰۷/۱۹`) or picked from a month calendar
  that starts on Saturday. Before, they showed the browser's Gregorian
  `mm/dd/yyyy` picker. The calendar arithmetic is checked day by day against
  ICU for 1950-2060. The report builder's period labels read "From date" /
  "To date" (the Persian "To" was the word for an email recipient).
- The audit trail reads in Persian: the detail of every event and sign-in is
  translated at display time (the stored record and the CSV keep the original
  English). `scripts/audit_messages.py` finds every sentence the code writes
  into the trail, and a test fails when a new one has no translation. The Logs
  page says it shows the latest 50 entries of each section and links to the
  audit trail.
- The sign-in history table (`login_logs`) is now created by a migration. It
  was only ever made by `create_all` at application start, so a database
  built by Alembic alone (a restore into an empty database, tools, CI) had no
  sign-in history table. CI now checks after the migrations that every model
  table exists (`scripts/check_migrations_cover_models.py`).
- License activation and offline license installation, accepted or refused,
  are written to the audit trail (`license.activate`,
  `license.offline_install`) with who did it (or the first-run screen), the
  address, and the license key masked to its first and last four characters.
- `SECRET_KEY` must have at least 32 characters and must not be a placeholder
  published in the repository (`config.py`, `.env.example`); NGCorion stops at
  start-up otherwise. It signs every session token and protects the stored
  secrets, and a short key can be brute-forced offline from one token.
- Password-reset codes are never written to the log. Without a mail server
  in `.env` (the appliance's default) the code used to be logged in clear
  instead of sent, so anyone able to read the log could reset any account.
  Reset emails now go through the mail server of System Configuration > SMTP
  (the one alerts and reports use), with the `.env` SMTP settings as a
  fallback; without either, nothing is sent and the log says so.

### Virtual appliance

- `appliance/build.sh` builds NGCorion as a virtual appliance: an OVA for
  VMware (EFI, Secure Boot, pvscsi, vmxnet3, deploy-time settings in
  vCenter), a VHDX for Hyper-V and a qcow2 for KVM/Proxmox. Ubuntu 24.04 LTS
  with Docker and every container image preloaded; no internet access needed.
- First start on the console: host name, network, NTP and the web
  administrator's password; the connection to lic.ngcorion.com is checked. Each appliance makes its
  own secrets, database password, certificate and machine-id. The same
  values can come from vCenter's OVF properties for an unattended start.
- Afterwards the console shows a menu (status, network, host name, NTP,
  license server connection check, restart, log, admin password reset,
  reboot, shut down).
  No shell, no SSH, no login prompt on any terminal, root locked, GRUB
  entries cannot be edited.
- Built on GitHub too (`.github/workflows/appliance.yml`): a version tag
  (`v2.1.0`) or a manual run builds the OVA, VHDX and qcow2 on GitHub's
  servers (KVM) and attaches them to a draft release, with SHA256SUMS.
  Images over GitHub's 2 GiB per-file limit come in parts; the release notes
  give the commands to join them.

### Compiled backend

- The production image runs the `app` package compiled to native modules
  (Cython 3.2), stripped of symbols; the `.py` sources are not in the image.
  Licensing, permissions, quotas and every feature module can no longer be
  read or edited in place on an installation. Three schema-only modules
  stay source (a Pydantic limitation); the build refuses to leave any
  licensing module uncompiled. Tests and development use the source; CI
  checks the image contains no other source and starts it.

### Documentation (AFTA)

- Persian user guide (`docs/fa/USER_GUIDE.md`, AGD_OPE), administrator guide
  covering delivery, installation, secure configuration and operation
  (`docs/fa/ADMIN_GUIDE.md`, AGD_PRE/AGD_OPE) and security architecture
  (`docs/fa/ARCHITECTURE.md`, ADV_ARC); the Security Target points to them.

### Asset icons
- New printer icon (printers, MFPs, copiers, plotters; by name, or by maker:
  Kyocera, Ricoh, Xerox, Konica, Lexmark, Brother), with the maker under it.
  The default "Printer" asset type uses it without any change. The desktop
  icon is now called "PC / workstation" so it is found as a PC.

### Fixes
- The audit trail's date range counts whole days in the time zone set in
  System Configuration, as reports do; before, a day ran from 03:30 to 03:30
  in Tehran (UTC days), so events after midnight landed on the wrong day.
- The asset overview (`/assets`) asks for an asset permission and the License
  page for a system administrator, as the menu already did: a direct URL now
  says "no access" instead of a half-empty page. The asset-limit dialog offers
  the License page to administrators only.
- The asset list no longer fails for everyone once the user who owned an
  asset is deleted (the owner becomes empty, which the API refused).
- Narrow screens: on a phone-sized screen (640 px or less) the menu starts as
  the icon rail, so pages keep their width; the audit trail's buttons wrap
  instead of running off the screen. A closed menu group's arrow points along
  the line (right in English, left in Persian). Checked in English and Persian
  at 1440, 1024, 768 and 390 px.
- The PDF guides print every nested list as a list: sub-items written with
  three spaces came out as a literal `*` (installation, Docker setup, audit
  credentials) or flat (audit trail review); the review section names the
  page's three tabs.
- `deploy.sh` starts the backend with `--remove-orphans`, so an upgrade from
  2.0.0 also stops the `redis` container the release no longer has.

Checked with an upgrade from 2.0.0 on real data: 2.0.0 database (users,
permissions, assets, sign-ins, audit events) migrated to this release, schema
identical to a fresh install, sign-in, audit trail and temporary passwords
working; a 2.0.0 backup restored into this release the same way, with the
audit trail still append-only.

### Asset groups, bulk edit and group audits

- Tags on assets ("pci", "web"), added or removed for many assets at once.
- Asset groups (Assets → Asset groups): dynamic, by conditions that all have
  to hold (type, Risk zone, owner, location, status, operating system,
  manufacturer, name, tag, IP range in CIDR), re-evaluated every time the
  group is used; or static, assets chosen by hand. The editor shows the
  assets that match while the conditions are written.
- Bulk edit in the asset list: add or remove tags, set owner, location,
  status or Risk zone, add to a static group, delete. Each changed asset gets
  its own change-history entry; deleting asks for the number of assets to be
  typed.
- Credential profiles (System Configuration, system administrators only):
  SSH, WinRM, SQL Server or Sophos API sign-in details defined once,
  encrypted under their own key and re-keyed on restore to another server.
  Write-only: a password is never shown again, an empty field keeps it. Each
  profile can be tried on one asset (a sign-in only), carries a password
  change period (default 90 days, alert "Credential profile due for a password
  change"), and shows when it was last used. Using a profile needs the new
  "Use credential profiles" permission.
- Group audits (Security assessment → Group audits): every asset of a group,
  one technology, one credential profile, up to 50 at a time. Each asset gets
  its normal audit session and score; the run lists what failed and why
  (sign-in refused, unreachable, not covered by the license, no address,
  interrupted by a restart, error) and retries only those. A restart marks
  audits that were running as interrupted and carries on with the queue.
  Stopping cancels what has not started. Alert "Group audit finished with
  failures".
- Scheduled audits can target a group with a credential profile instead of
  one asset with typed credentials; no credentials are stored in the
  schedule. A group or profile used by a schedule cannot be deleted.
- Every group, profile, bulk change and group audit is in the audit trail
  (who, what, which profile), without any secret.

### One page per asset

- Clicking an asset's name in the inventory opens its page
  (/assets/inventory/<id>): type, status, address, tags, groups (static or by
  rule), license coverage; risk score, latest compliance, vulnerabilities,
  open and overdue remediation, last configuration backup and changes outside
  NGCorion, SNMP and syslog; open alerts; latest audit of each technology,
  top vulnerabilities, remediation items, backups with "What changed",
  details, monitoring, topology neighbours, software and hardening; and a
  timeline across all modules.
- Each section shows only when the user may read its module; audits and
  hardening follow the same "own items only" rule as their own pages
  (GET /api/assets/{id}/360).
- Persian: a middle dot next to a number read as a Persian zero ("۲۴ ·"
  looked like "۲۴۰"); Persian now separates with "،", and a test keeps it so.
  Backup coverage by device type uses Persian digits.

### Device health over SNMP

- Every NOC poll also reads CPU, memory, disk and temperature: HOST-RESOURCES-MIB
  (Linux, Windows), net-snmp's UCD-SNMP-MIB, ENTITY-SENSOR-MIB, and the Cisco
  (CPU, memory pools, environment) and FortiGate MIBs. The host page has a
  "Device health" card (the four values, the file systems, the temperature
  sensors, the device's own uptime — hrSystemUptime, not the SNMP agent's),
  charts of each value in History (6 hours by default), and the restarts NOC
  noticed. The host list has CPU, memory and disk columns; the asset page shows
  them too.
- A restart is noticed when the uptime starts again from zero (the 497-day
  counter wrap is not one) and raises the alert "Device restarted".
- New alerts: "CPU usage high" and "Memory usage high" (every poll of the window
  at or above the threshold, 90% for 10 / 15 minutes by default — a short spike
  does not count), "Disk almost full" (90%) and "Temperature high" (70 °C,
  critical).
- Fixes: on the host page in Persian the interface filters compared translated
  labels with English groups, so the interface table could show nothing;
  interface status and counts are now translated and use Persian digits. The
  host page fits a phone screen.

### Syslog from the assets

- NGCorion receives syslog on UDP and TCP port 514 (Network & monitoring ->
  Syslog). Off until a system administrator turns it on; on, off, UDP/TCP,
  retention (30 days by default), a disk budget (5 GB, the oldest go first)
  and which levels are kept take effect within 15 seconds, without a restart,
  and are in the audit trail.
- Only addresses of assets in the inventory are kept; messages from other
  addresses are dropped and those addresses listed, so the device can be
  added. Per-address rate limit, message size limit, TCP connection limits.
- RFC 5424, BSD/RFC 3164 (Linux, Cisco IOS with sequence numbers and
  origin-id, Cisco NX-OS with the year first, a relay's header in front of
  the device's own) and FortiGate key=value logs are parsed into time, host,
  program or event name, severity and text; TCP takes one message per line or
  octet counting.
- The page: messages with asset, severity, period and text filters, live
  refresh, older pages, CSV export; which assets send and when they last did;
  the addresses outside the inventory; how to set up Cisco IOS, FortiGate and
  rsyslog.
- Alerts: "Severe syslog message" (critical or worse by default), "Asset
  stopped sending syslog" (24 hours), "Syslog from an address outside the
  inventory" (off by default), "Syslog intake not listening".
- docker-compose publishes the host's port 514 (UDP/TCP) to the container's
  5514 (the app does not run as root); SYSLOG_BIND_ADDR limits it to one
  interface. Syslog messages are part of the optional "NOC monitoring
  history" in NGCorion backups.

### Scheduled configuration backups and change detection

- Backup schedules (Device backups → Backup schedules): back up every device
  of an asset group (Cisco IOS, FortiGate, Linux, Apache, MongoDB) with an
  SSH credential profile, nightly at 02:00 by default, up to 50 devices at a
  time. Each run lists every device's result (first backup, unchanged,
  changed with lines added and removed) and why a device failed (sign-in
  refused, unreachable, no address); failed devices can be retried. No
  credentials are stored in the schedule.
- An unchanged configuration is not stored again; the latest backup records
  that the device was still the same ("still the same on …").
- Every backup — by hand, before a hardening or a restore, scheduled — is
  compared with the device's previous one. Cisco IOS and FortiOS are compared
  as configuration trees, so timestamps and counters that differ between two
  captures are not a change; Linux, Apache and MongoDB file bundles are
  compared file by file.
- A change is "by NGCorion" when a hardening or a restore ran on the device
  between the two backups, otherwise "outside NGCorion". New alerts
  "Configuration changed outside NGCorion" (warning, on by default),
  "Configuration changed by NGCorion" (information, off by default) and
  "Group backup finished with failures"; each links to the comparison.
- Compare any two backups of a device ("What changed", or pick two and
  "Compare selected"); the backup list shows the change badge, the number of
  scheduled backups and of changes, and filters for changes and source.
- Retention: backups identical to the previous one are removed after 90 days
  (configurable, 7–3,650); every changed version, the latest and first backup
  of each device, and backups a hardening or restore relies on are kept.
- Backup on a reported change: when a device sends syslog to NGCorion, the
  configuration change it reports (Cisco IOS/IOS-XE `%SYS-5-CONFIG_I`, NX-OS
  `%VSHD-5-VSHD_SYSLOG_CONFIG_I`, FortiGate "Object attribute configured" /
  "Configuration changed") is recorded with who made it and from which
  address. About a minute after the last change the device alone is backed up
  with the credential profile of the enabled backup schedule that covers it,
  and compared as usual; at most once every 5 minutes per device. The backup
  (source "On reported change"), the comparison, the "Configuration changed
  outside NGCorion" alert and the asset's timeline say who changed it and from
  where. Without a covering schedule the new alert "Configuration change
  reported, no backup taken" is raised. On by default; Syslog → Settings
  turns it off.
- Fixes: scheduled group audits are labelled "Group audit (…)" in the
  schedule list; schedule times, next run and history use Persian digits and
  dates, and the run status is translated.

### Sign-in with Active Directory / LDAP
- Users sign in with their organization account. Active Directory, or another
  LDAP directory (OpenLDAP, FreeIPA); several servers tried in order; LDAPS or
  StartTLS, the server certificate checked against the uploaded CA (or the
  system's) and the server name; or, chosen explicitly for directories without
  a certificate, plain LDAP on 389 (passwords cross the network unencrypted:
  the settings show a warning and choosing it is in the audit trail; a DC that
  requires LDAP signing refuses it with a clear message). The service account's password is stored
  encrypted and never sent back to the browser.
- Directory groups map to a role and, below system administrator, module
  permissions; a user gets the highest role and every permission of their
  mapped groups, nested groups included. A user in no mapped group, or
  disabled in the directory, cannot sign in (and sees only "incorrect username
  or password"; the reason is in the audit trail).
- The account is made at the first sign-in; its role and permissions follow
  the directory at every sign-in and every 15 minutes, when accounts disabled,
  deleted or out of every mapped group in the directory are turned off.
  Turning directory sign-in off ends every directory session at once.
- Local accounts always sign in with their own password, so a local
  administrator still gets in when the directory is down; that raises the new
  "Local administrator signed in" alert. New alert: "Directory not reachable".
- Directory accounts have no password change or reset in NGCorion, and their
  name, role and permissions cannot be edited there (User Management marks
  them "AD"). Two-step sign-in applies to them by role, its password step
  checked against the directory.
- Settings: System Configuration → Active Directory / LDAP, with connection
  test, group search, a test of one user (groups and resulting role), and the
  last account check. Tested against Samba AD (LDAPS, StartTLS, nested groups,
  disabled accounts, failover) and OpenLDAP. New dependency: ldap3. Migration
  `e5a7c9b1d3f8`.

### Two-step sign-in (FIA_UAU.5)
- After the password, a 6-digit code from an authenticator app (TOTP, RFC
  6238: Google Authenticator, Microsoft Authenticator, FreeOTP...), or a
  one-time recovery code. Works offline; no SMS or email. A code is accepted
  once, 30 s either side of now. The password step alone returns only a
  five-minute token that opens nothing but the code step; wrong codes count
  towards the sign-in lockout.
- Setup from the account menu: password, QR code (or the key by hand), first
  code, then 8 recovery codes shown once (copy or save). Moving to a new phone
  needs a code from the old one; new recovery codes and turning it off need
  the password and a code.
- Policy (System Configuration → Two-step sign-in, system administrators):
  the roles that must use it (default: admin and manager) and the days such a
  user has to set it up from their next sign-in (default 7; system
  administrators none). After that, the session reaches only the setup.
- Turning it on or off, moving it, or a reset ends the user's other sessions.
  A system administrator resets it for a user who lost the phone and the codes
  (User Management, which also shows everyone's state); the VM console's
  "reset the web administrator's password" resets it for `admin` too.
- The secret is encrypted under its own key (and re-encrypted when a backup
  is restored on another server); recovery codes are kept only as salted
  PBKDF2 hashes. Every step is in the audit trail.
- Upgrade note: system administrators set it up at their first sign-in after
  the upgrade (migration `d4f6a8c0e2b6`).

### Audit storage (FAU_STG.3 / FAU_STG.4)
- When free disk falls below `STORAGE_CRITICAL_MB` (500 MB by default),
  changes are refused (507) to everyone but system administrators, and
  scheduled audits, discovery, reports and backups wait; reading and signing
  out go on. Entering and leaving this state is recorded in the audit trail
  and shown in the health check (`storage_guard`), which also gives the size
  of the database, the audit trail and the sign-in history. The "Disk space
  low" alert (2 GB) warns well before.
- New archive tool, `python -m app.modules.audit_archive export | verify |
  purge`: writes the audit events and sign-ins older than a day to a zip with
  a SHA-256 manifest, and removes from the database only rows that are byte
  for byte in a verified archive, recording the removal (count, cut-off,
  archive hash) in the trail. Tested at 300,000 events: 5 s to archive (4 MB),
  7 s to remove.
- Fix: `python -m app.modules.sysbackup.cli` (backup and restore from the
  command line) failed in the production image, whose modules are compiled
  and have no code object for `python -m`. Command-line entry points now stay
  Python source (`RUN_AS_MAIN` in `scripts/compile_app.py`); a test checks
  every `python -m` the documentation gives.

### Performance
- The audit trail's search box uses a trigram index (PostgreSQL's pg_trgm, in
  its own schema `ngcorion_ext`): at a million events a search takes 13-200 ms
  instead of 1.4-1.9 s, and a filtered CSV export 50 ms instead of 0.8 s.
  Building the index on an existing million-event trail takes about 35 s
  during the upgrade. Where pg_trgm cannot be created the migration skips the
  index with a warning and search works as before.

Load-tested at 2,500 assets, a million audit events and 200,000 sign-ins:
asset list (all 2,500) 220 ms, every audit trail and sign-in history page,
filter and facet under 250 ms.

### A clearer menu
- The sidebar follows the work: Assets, Security assessment (risk, audits,
  CVE), Remediation & hardening, Device backups, Network & monitoring,
  Reports, Administration; at most seven entries per group, plain names
  instead of the two "Operation & Device" entries.
- Group headings open and close their group (the current page's group stays
  open, the rest is remembered per browser); the overview pages that used to
  open only from a clickable heading are entries of their own. Collapsed, each
  group is an icon whose entries appear beside it. Entries are real links.
- Every entry needs the permission its page needs: Risk and License were shown
  to everyone, and a user without the risk permission landed on "no access".
  The license and NGCorion backup entries are for system administrators.
- Logs and the audit trail are one page, "Logs and audit trail", with the
  module activity as its third tab; `/settings/logs` opens that tab. The CVE
  database moved to Administration. Page URLs are unchanged.

### Documents as PDF
- The Persian user guide, admin guide, security architecture and Security
  Target are printed to PDF by `scripts/docs_pdf.py`: right-to-left A4 in the
  Vazirmatn font, a cover (product, version, document id, Jalali date), a
  linked table of contents, bookmarks and page numbers; links between the
  documents lead to the other PDFs. CI builds them on every push (artifact
  `ngcorion-docs-fa-pdf`) and the appliance release attaches them, listed in
  `SHA256SUMS`. The Markdown stays the source.

### Smaller deployment

- The Redis container is gone from `docker-compose.yml` and the appliance: no
  NGCorion code used it (the license server, which did, has its own). One
  service, image and volume fewer to run, patch and secure.

### Code standards

- The backend is linted in CI with ruff (pyflakes and syntax errors: unused or
  duplicate imports and variables, undefined names; rules in `pyproject.toml`).
  About 200 unused imports, dead variables and duplicate imports were removed;
  behaviour is unchanged.

### Dependencies

- React 19, Vite 8, ESLint 10; FastAPI 0.142, Alembic 1.20, Netmiko 4.8,
  cryptography 50.0.2.

### Upgrade notes

- Docker installations: start with `docker compose up -d --remove-orphans` so
  the old `redis` container is removed; the `redis_data` volume can then be
  deleted (`docker volume ls`, `docker volume rm <project>_redis_data`). The
  appliance does this by itself.
- Docker installations: check that `SECRET_KEY` in `.env` has at least 32
  characters (the appliance generates 64). A shorter key now stops the start.
  Replacing it signs everyone out and makes stored secrets (scheduled-job
  credentials, SNMP, SMTP, backup destinations) unreadable: re-enter them, or
  restore a system backup, which re-encrypts them under the new key.
- Images built before this release contain the `.env` of the checkout they
  were built from, if it had one. After upgrading, delete the old backend
  image (Compose named it after the folder, e.g. `ngcorion-backend`; see
  `docker images`), and rotate those secrets if such an image ever left the host.
- Requires the matching license server release (signed answers, migration
  005). Upgrade the license server first; older NGCorion releases keep working
  against it.
- This release trusts the license server key `02f8c805e424e285`
  (lic.ngcorion.com, `app/core/license_keys.py`); the license server must sign
  with the matching private key (`GET /api/signing-key` shows its key id).
- System administrators (role `admin`) set up two-step sign-in at their first
  sign-in after the upgrade: until then the session opens only the setup.
  Managers get 7 days. Have an authenticator app ready; the policy is in System
  Configuration → Two-step sign-in.
- docker-compose now mounts the host's `/etc/machine-id`. On the first
  validation after the upgrade each installation re-activates once, binding
  its license to the real machine; a second copy of the same installation is
  then refused. To move a license to new hardware later, use "Release
  machine" in the license admin UI.

### Upgrade test

- 2.0.0 (`7f5be33`) to 2.1.0 on a database created and filled by 2.0.0 (40
  assets, two users, 25 sign-ins, 15 audit events): every migration ran
  (`f9c2d4e6a8b0` → `d1f3a5c7e9b2`); the upgraded schema equals a fresh
  install's column for column and index for index; the 2.0.0 password still
  signs in, the admin is taken to the two-step setup first, and all main pages
  then open without a server or page error; the 2.0.0 assets, audit events
  and sign-in history are there, and the 2.0.0 user's permissions still apply.
- Full test suite on a freshly migrated database: 3,366 passed, 60 skipped.

## 2.0.0 — 2026-10-04

### New audit and hardening targets

All on the shared benchmark engine (`app/modules/benchmark`), with typed
hardening parameters, verified fixes and Harden All:

- Active Directory (CIS domain-controller profile plus domain checks beyond CIS)
- Windows DNS Server (DISA STIG) and Windows DHCP Server (Microsoft guidance)
- IIS 10 (CIS)
- Docker (CIS Docker) and Kubernetes (CIS Kubernetes, kubeadm)
- MySQL 8 (CIS)
- VMware ESXi 7/8 (CIS)
- NGINX (CIS NGINX)
- Sophos Firewall (vendor hardening guide, XML API)

### New modules

- CVE database with online and signed offline updates (NVD, CISA KEV, EPSS)
- Distribution security advisories (Ubuntu, Debian, RHEL family via OSV)
- Software inventory per asset, with change history and CVE matching on real versions
- Remediation tracking with deadlines and risk acceptance (four-eyes approval)
- Reports: catalog of 14 reports, PDF and Excel, archive, schedules and e-mail
- Alerts and notifications (e-mail, SMS, syslog, webhooks)
- NGCorion self-backup: encrypted backups, remote destinations, verified restore
- Configuration restore from device backups with automatic revert
- Bilingual interface (Persian, right-to-left with Solar Hijri dates, and English)
- Target picker driven by the target catalog; an icon for every asset type

### Security

- Server-side logout: access tokens carry an id and are revoked on logout.
- Passwords chosen by someone else (new accounts, the first administrator)
  must be changed at first login; users can change their own password.
  `scripts/init_db.py` no longer creates a default password.
- Every audit session listing, count, history and statistic is limited to the
  caller's own sessions for non-admins, as the detail endpoints already were.
  Hardening requests must own the session, finding or action they name.
- Hardening parameters: numbers are substituted in canonical form.
- PDF reports load only the bundled fonts; Excel exports never store a formula.
- Discovery port lists, Sophos API entity names and OSV URLs are validated
  or encoded before use.
- python-jose replaced by PyJWT; CI checks dependencies for known
  vulnerabilities (pip-audit, npm audit) and Dependabot proposes updates.
- The backend container runs as an unprivileged user.

### Fixes

- Background tasks run once across uvicorn workers (leader election).
- Health checks count only this database's advisory locks.
- The hardening audit log now records the asset and session of a preview
  (it read a relationship that does not exist).
- Discovery records the MAC vendor of hosts.

### For developers

- `README.md`, `docs/ARCHITECTURE.md` and `docs/DEVELOPER_GUIDE.md` describe
  the system, its security rules and how to extend it.
- Every backend module, public class and function has a docstring; every
  frontend file starts with a comment saying what it is for.
- CI runs the backend tests on PostgreSQL, the frontend lint (no warnings),
  tests, translation check and build.

### Upgrade notes

- Apply the migrations (`alembic upgrade head`; the container does this on
  start). New tables include `revoked_tokens`; `users` gains
  `must_change_password`.
- Existing users are not forced to change their password. Accounts created
  from now on are.
- Non-admin users now see only their own audit sessions in every list.
