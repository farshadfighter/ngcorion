# FortiGate CIS Benchmark Audit & Hardening Module

## Overview

This module audits FortiGate firewalls against the **CIS FortiGate Benchmark**
(`docs/forti_cis_benchmark.docx`) and applies guided hardening. The control
catalog implements the benchmark checklist **exactly**:

- **53 recommendations** across the benchmark's 8 sections
- **28 Automated** (verified from configuration and scored) +
  **25 Manual** (evidence-only, excluded from the compliance score)
- **VDOM-aware**: each control is evaluated in the correct scope
  (`global`, per-VDOM, or management-VDOM) and, on VDOM-enabled devices, the
  per-VDOM controls are evaluated for every active VDOM.

The catalog is the single source of truth in
[`audit/rules.py`](audit/rules.py); the benchmark section ↔ control-ID mapping
lives in [`audit/cis_map.py`](audit/cis_map.py). The full checklist is
reproduced in [Audit Benchmark Checklist](#audit-benchmark-checklist) below.

## Architecture

```
app/modules/fortinet/
├── __init__.py
├── audit/
│   ├── ssh_client.py      # SSH client: VDOM discovery + scoped collection
│   ├── rules.py           # The 53 CIS controls (catalog / source of truth)
│   ├── cis_map.py         # CIS section ↔ control-ID mapping
│   ├── service.py         # Audit orchestration, scoring, per-VDOM evaluation
│   └── router.py          # FastAPI endpoints (/api/audit/fortinet/*)
├── hardening/
│   ├── ssh_executor.py    # Applies remediation commands over SSH
│   ├── command_templates.py
│   ├── command_parser.py
│   ├── parameter_metadata.py
│   ├── service.py         # Hardening orchestration + backup
│   └── router.py          # FastAPI endpoints (/api/hardening/fortinet/*)
└── README.md              # This file
```

## Scope model

FortiOS `show` omits values left at their default, and settings live in
different configuration contexts. Each control therefore declares a **scope**
that tells the SSH engine where to read it:

| Scope       | Read from                              | Notes                                            |
|-------------|----------------------------------------|--------------------------------------------------|
| `global`    | `config global` (or flat top-level)    | Read once per device                             |
| per-VDOM    | inside each `config vdom` / `edit <n>` | Evaluated once **per active VDOM**               |
| mgmt-VDOM   | the management VDOM (`root`) only      | Device-wide settings that live under a VDOM      |

Evaluation respects the "show omits defaults" behaviour:

- a secure setting that is **default-ON**  → pass when `set X disable` is **absent**
- a secure setting that is **default-OFF** → pass when `set X enable` is **present**
- numeric thresholds → compared against the control's documented default when the line is omitted

Manual controls cannot be reliably proven from config alone, so they run their
command, capture evidence, and are **excluded from the compliance score**.

## Audit Benchmark Checklist

All 53 CIS FortiGate Benchmark recommendations, with the internal control that
backs each one, the scope it is read in, and the command it inspects.
**Type** is the benchmark's own classification.

### 1. Network Settings

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 1.1 | Ensure DNS server is configured | Automated | `FG-BL-043` | global | `show system dns` |
| 1.2 | Ensure intra-zone traffic is not always allowed | Manual | `FG-NET-001` | per-VDOM | `show system zone` |
| 1.3 | Disable all management related services on WAN port | Manual | `FG-NET-002` | global | `show system interface` |

### 2. System Settings

#### 2.1 General Settings

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 2.1.1 | Ensure 'Pre-Login Banner' is set | Automated | `FG-BL-092` | global | `show system global` |
| 2.1.2 | Ensure 'Post-Login-Banner' is set | Automated | `FG-SYS-001` | global | `show system global` |
| 2.1.3 | Ensure timezone is properly configured | Manual | `FG-SYS-002` | global | `show system global` |
| 2.1.4 | Ensure correct system time is configured through NTP | Automated | `FG-BL-040` | global | `show system ntp` |
| 2.1.5 | Ensure hostname is set | Automated | `FG-SYS-003` | global | `show system global` |
| 2.1.6 | Ensure the latest firmware is installed | Manual | `FG-SYS-004` | global | `get system status` |
| 2.1.7 | Disable USB Firmware and configuration installation | Automated | `FG-SYS-005` | global | `show system auto-install` |
| 2.1.8 | Disable static keys for TLS | Automated | `FG-SYS-006` | global | `show system global` |
| 2.1.9 | Enable Global Strong Encryption | Automated | `FG-BL-090` | global | `show system global` |
| 2.1.10 | Ensure management GUI listens on secure TLS version | Manual | `FG-BL-005` | global | `show system global` |

#### 2.2 Password Policy

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 2.2.1 | Ensure 'Password Policy' is enabled | Automated | `FG-BL-030` | mgmt-VDOM | `show system password-policy` |
| 2.2.2 | Ensure administrator password retries and lockout time are configured | Automated | `FG-PW-001` | global | `show system global` |

#### 2.3 SNMP

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 2.3.1 | Ensure only SNMPv3 is enabled | Automated | `FG-BL-050` | global | `show system snmp community` |
| 2.3.2 | Allow only trusted hosts in SNMPv3 | Manual | `FG-SNMP-001` | global | `show system snmp user` |

#### 2.4 Administrators and Admin Profiles

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 2.4.1 | Ensure default 'admin' password is changed | Manual | `FG-BL-021` | global | `show system admin` |
| 2.4.2 | Ensure all the login accounts having specific trusted hosts enabled | Manual | `FG-BL-020` | global | `show system admin` |
| 2.4.3 | Ensure admin accounts with different privileges have their correct profiles assigned | Manual | `FG-ADM-001` | global | `show system admin` |
| 2.4.4 | Ensure idle timeout time is configured | Automated | `FG-BL-004` | global | `show system global` |
| 2.4.5 | Ensure only encrypted access channels are enabled | Automated | `FG-BL-002` | global | `show system global` |
| 2.4.6 | Apply Local-in Policies | Manual | `FG-LIP-001` | per-VDOM | `show firewall local-in-policy` |
| 2.4.7 | Ensure default Admin ports are changed | Manual | `FG-BL-007` | global | `show system global` |

#### 2.5 High Availability

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 2.5.1 | Ensure High Availability configuration is enabled | Automated | `FG-HA-004` | global | `show system ha` |
| 2.5.2 | Ensure 'Monitor Interfaces' for High Availability devices is enabled | Automated | `FG-HA-005` | global | `show system ha` |
| 2.5.3 | Ensure HA Reserved Management Interface is configured | Manual | `FG-HA-006` | global | `show system ha` |

### 3. Policy and Objects

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 3.1 | Ensure that unused policies are reviewed regularly | Manual | `FG-POL-001` | per-VDOM | `show firewall policy` |
| 3.2 | Ensure that policies do not use 'ALL' as Service | Automated | `FG-BL-080` | per-VDOM | `show firewall policy` |
| 3.3 | Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB | Manual | `FG-POL-002` | per-VDOM | `show firewall policy` |
| 3.4 | Ensure logging is enabled on all firewall policies | Manual | `FG-BL-082` | per-VDOM | `show firewall policy` |

### 4. Security Profiles

#### 4.1 Intrusion Prevention System (IPS)

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 4.1.1 | Detect Botnet connections | Manual | `FG-IPS-001` | per-VDOM | `show firewall policy` |
| 4.1.2 | Apply IPS Security Profile to Policies | Manual | `FG-UTM-003` | per-VDOM | `show firewall policy` |

#### 4.2 Antivirus

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 4.2.1 | Ensure Antivirus Definition Push Updates are Configured | Automated | `FG-AV-001` | global | `show system autoupdate push-update` |
| 4.2.2 | Apply Antivirus Security Profile to Policies | Manual | `FG-UTM-002` | per-VDOM | `show firewall policy` |
| 4.2.3 | Enable Outbreak Prevention Database | Automated | `FG-AV-002` | per-VDOM | `show antivirus profile` |
| 4.2.4 | Enable AI/heuristic based malware detection | Automated | `FG-AV-003` | per-VDOM | `show antivirus settings` |
| 4.2.5 | Enable grayware detection on antivirus | Automated | `FG-AV-004` | per-VDOM | `show antivirus settings` |

#### 4.3 DNS Filter

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 4.3.1 | Enable Botnet C&C Domain Blocking DNS Filter | Automated | `FG-DNS-001` | per-VDOM | `show dnsfilter profile` |
| 4.3.2 | Ensure DNS Filter logs all DNS queries and responses | Manual | `FG-DNS-002` | per-VDOM | `show dnsfilter profile` |
| 4.3.3 | Apply DNS Filter Security Profile to Policies | Manual | `FG-DNS-003` | per-VDOM | `show firewall policy` |

#### 4.4 Application Control

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 4.4.1 | Block high risk categories on Application Control | Manual | `FG-APP-001` | per-VDOM | `show application list` |
| 4.4.2 | Block applications running on non-default ports | Automated | `FG-APP-002` | per-VDOM | `show application list` |
| 4.4.3 | Ensure all Application Control related traffic is logged | Manual | `FG-APP-003` | per-VDOM | `show application list` |
| 4.4.4 | Apply Application Control Security Profile to Policies | Manual | `FG-APP-004` | per-VDOM | `show firewall policy` |

### 5. Security Fabric

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 5.1.1 | Enable Compromised Host Quarantine | Automated | `FG-FAB-001` | global | `show system automation-stitch` |
| 5.2.1.1 | Ensure Security Fabric is Configured | Automated | `FG-FAB-002` | global | `show system csf` |

### 6. VPN

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 6.1.1 | Apply a Trusted Signed Certificate for VPN Portal | Manual | `FG-VPN-SSL-003` | per-VDOM | `show vpn ssl settings` |
| 6.1.2 | Enable Limited TLS Versions for SSL VPN | Manual | `FG-VPN-SSL-001` | per-VDOM | `show vpn ssl settings` |

### 7. Users and Authentication

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 7.1 | Configuring the maximum login attempts and lockout period | Automated | `FG-USER-001` | per-VDOM | `show user setting` |

### 8. Logs and Reports

| CIS § | Recommendation | Type | Control ID | Scope | Reads |
|-------|----------------|------|------------|-------|-------|
| 8.1.1 | Enable Event Logging | Automated | `FG-LOG-001` | per-VDOM | `show log eventfilter` |
| 8.2.1 | Encrypt Log Transmission to FortiAnalyzer / FortiManager | Automated | `FG-LOG-002` | global | `show log fortianalyzer setting` |
| 8.3.1 | Centralized Logging and Reporting | Automated | `FG-FAZ-001` | global | `show log fortianalyzer setting` |

**Totals:** 53 controls — 28 Automated (scored) · 25 Manual (evidence-only).

> Legend — **Automated**: verified programmatically from configuration and
> included in the compliance score. **Manual**: requires human review; the
> command output is captured as evidence but does not affect the score.

## VDOM-aware evaluation

1. The SSH client checks whether the device is VDOM-enabled
   (`is_vdom_enabled()`).
2. If it is, active VDOMs are enumerated (`enumerate_vdoms()`); the audit can
   target one VDOM or every VDOM.
3. `global` and `mgmt-VDOM` controls are evaluated once; per-VDOM controls are
   evaluated for each target VDOM, and each result is stored with its `vdom`
   label so the UI can group findings by VDOM.

## API endpoints

### Audit (`/api/audit/fortinet`)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/audit/fortinet/vdoms/discover` | Discover active VDOMs before auditing |
| POST | `/api/audit/fortinet/execute` | Run the CIS audit (one VDOM or all) |
| GET  | `/api/audit/fortinet/sessions` | List audit sessions |
| GET  | `/api/audit/fortinet/sessions/{id}` | Session details + compliance summary |
| GET  | `/api/audit/fortinet/sessions/{id}/results` | Per-check results (incl. `vdom`) |
| DELETE | `/api/audit/fortinet/sessions/{id}` | Delete a session |

### Hardening (`/api/hardening/fortinet`)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/hardening/fortinet/vdoms/discover` | Discover active VDOMs before hardening |
| POST | `/api/hardening/fortinet/preview` | Preview the commands a fix would run |
| POST | `/api/hardening/fortinet/execute` | Apply a single remediation |
| POST | `/api/hardening/fortinet/batch-execute` | Apply multiple remediations |
| POST | `/api/hardening/fortinet/auto-harden-defaults` | Apply default hardening set |
| GET  | `/api/hardening/fortinet/actions` | List hardening actions |

### Example: discover VDOMs

```bash
curl -X POST http://localhost:8000/api/audit/fortinet/vdoms/discover \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "password",
    "ssh_port": 22
  }'
```

```json
{
  "asset_id": 42,
  "asset_name": "fw-hq-01",
  "target_ip": "192.168.1.1",
  "vdoms": ["root", "VDOM_1", "VDOM_2"]
}
```

### Example: execute audit

```bash
curl -X POST http://localhost:8000/api/audit/fortinet/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "password",
    "ssh_port": 22,
    "vdom": null,
    "profile": "FULL"
  }'
```

> `vdom: null` audits **every** VDOM on a VDOM-enabled device; pass a name to
> scope the audit to a single VDOM. `ssh_port` may be set if the device does
> not use the default port 22.

A per-check result carries the backing control ID in `check_number` (map it to
the CIS section via [`cis_map.py`](audit/cis_map.py)) and, on VDOM devices, the
originating VDOM in `vdom`:

```json
[
  {
    "id": 1,
    "check_number": "FG-BL-092",
    "check_title": "Pre-Login Banner is set",
    "severity": "Low",
    "level": "L1",
    "vdom": "global",
    "status": "pass",
    "evidence_snippet": "set pre-login-banner enable",
    "checked_at": "2026-06-28T10:01:00Z"
  }
]
```

## Frontend

The audit (`AuditingForm`) and hardening (`HardeningConnectionForm`,
`CredentialsForm`) flows expose, for FortiGate:

- a **manual SSH port** field, and
- a **Detect VDOMs** button that calls the discovery endpoint and lists the
  active VDOMs so the operator can target one or audit all of them.

## Security considerations

1. **Credentials** are never stored — they are used only for the duration of an
   audit/hardening run.
2. **Audit is read-only** — every audit command is a non-modifying
   `show` / `get`.
3. **VDOM isolation** — each VDOM is read in its own context.
4. **Hardening** changes are previewable and can be backed up before they are
   applied.

## Dependencies

- `netmiko` — SSH automation (FortiGate driver)
- PostgreSQL (via SQLAlchemy) — audit sessions and results storage

## Tests

```bash
pytest tests/test_fortinet_rules.py tests/test_fortinet_ssh_scope.py
```

These assert the catalog is exactly the 53 CIS controls (28 Automated /
25 Manual), that every `cis_map` section maps 1:1 to a defined control, and that
each control is collected in its correct VDOM scope.
