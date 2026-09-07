# SSH host-key verification

Every audit and hardening connection NGCorion makes to a managed device — Linux,
Apache, MongoDB, Cisco IOS, FortiGate — now verifies the device's SSH host key
before sending any credential.

Previously all five SSH clients accepted whatever key a device presented
(`paramiko.AutoAddPolicy()` in the hardening runner; netmiko's identical default
in the audit clients). Anyone able to sit on the network path between NGCorion
and a device could therefore impersonate that device, capture the administrator
credentials the session sends, and rewrite the remediation commands in flight —
on the very connections whose purpose is to secure the device.

Implementation: `app/core/ssh_host_keys.py`. Item 1.3 in
`SECURITY_REMEDIATION_CHECKLIST.md`.

---

## Policy modes

Set with `SSH_HOST_KEY_POLICY` (see `.env.example`).

### `tofu` — trust on first use (default)

The first time NGCorion connects to a device, its host key is pinned to the
known-hosts store and a `WARNING` is logged with the fingerprint:

```
[SSH] TRUST ON FIRST USE: pinned ecdsa-sha2-nistp256 host key for 10.20.0.7:22
(SHA256:9m0F…u2c). Verify this fingerprint out of band; every later connection
must present the same key or it will be refused.
```

Every later connection to that device must present the same key. A different key
is refused, and the operator sees an explicit host-key error rather than a
misleading "authentication failed".

This is the default because it requires **no** manual provisioning: devices you
already audit keep working exactly as before, while the persistent-interception
and device-swap cases become detectable and blockable.

Residual risk: an attacker already in position during the very first connection
to a given device would have their key pinned as legitimate. Verify the logged
fingerprints against the devices (`ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`
on a Linux host, `get system fortiguard`/console on network gear), then move to
`strict`.

### `strict`

Nothing is pinned automatically: a device must already be in the store or the
connection is refused before any credential is sent. Use this once the fleet's
keys are pinned and verified.

There is deliberately **no** mode that disables verification. A device whose key
legitimately changed is handled per-host (below), which is auditable and cannot
be left globally switched on by accident.

---

## The known-hosts store

Standard OpenSSH `known_hosts` format, so it can be inspected and edited with the
usual tooling (`ssh-keygen -F`, `ssh-keygen -R`).

Location — `SSH_KNOWN_HOSTS_FILE` if set, otherwise auto-detected:

| Environment | Path | Persistence |
|---|---|---|
| Docker (default deployment) | `/etc/ngcorion/known_hosts` | Bind-mounted from the host in `docker-compose.yml`, so pins survive container recreation |
| Bare metal / development | `~/.ngcorion/known_hosts` | Home directory of the user running the app |

The file is created `0600` on first pin. Entries are keyed by host **and port**
(`10.0.0.1` for port 22, `[10.0.0.1]:2222` otherwise), matching paramiko's and
OpenSSH's own convention.

Writes are safe under `uvicorn --workers 4`: each read-modify-write takes an
`flock` and replaces the file atomically, so two workers pinning different
devices simultaneously cannot clobber each other.

---

## Operational procedures

### A device was legitimately reinstalled, replaced or re-keyed

Connections will fail with `host_key_mismatch` until the old pin is removed.

1. Confirm the change is expected (maintenance window, RMA, reimage).
2. Verify the **new** fingerprint out of band — from the device console, not
   over the connection you are about to trust.
3. Remove the old entry:

   ```bash
   # inside the backend container, or on the host with the same path
   ssh-keygen -R '10.20.0.7'            # port 22
   ssh-keygen -R '[10.20.0.7]:2222'     # non-default port
   # -f /etc/ngcorion/known_hosts if it is not your default known_hosts
   ```

   Equivalently, from Python: `app.core.ssh_host_keys.forget_host("10.20.0.7", 22)`.
4. Reconnect. Under `tofu` the new key is pinned (and logged); under `strict`,
   add it explicitly first (below).

### Pre-provisioning keys (required for `strict`)

```bash
ssh-keyscan -p 22 10.20.0.7 >> /etc/ngcorion/known_hosts
```

Then verify each fingerprint against the device before trusting the file:

```bash
ssh-keygen -lf /etc/ngcorion/known_hosts
```

`ssh-keyscan` learns the key over the network, so it carries the same
first-contact assumption as `tofu` — the out-of-band comparison is what makes it
trustworthy.

### Migrating an existing deployment to `strict`

1. Run normally under `tofu` until every device has been contacted once.
2. Review `/etc/ngcorion/known_hosts` and verify the fingerprints.
3. Set `SSH_HOST_KEY_POLICY=strict` and restart.

New devices then need step "Pre-provisioning" before their first audit.

---

## What operators will see

| Situation | Result | Error type |
|---|---|---|
| Known device, unchanged key | Connects normally | — |
| New device, `tofu` | Connects; key pinned; `WARNING` logged with fingerprint | — |
| New device, `strict` | Refused before authentication | `host_key_unknown` |
| Key changed / MITM | Refused, both fingerprints reported | `host_key_mismatch` |
| Host key unreadable (probe failed) | Refused — never trusted blindly | `host_key_unknown` |

All of these surface through the existing `SSHHostKeyError` handling the
hardening/audit routers already had, so they render as normal API errors with
remediation suggestions attached.

---

## Performance

Steady state adds nothing: for a device that is already pinned, verification is a
local file lookup plus the host-key comparison paramiko performs during the
key exchange it was doing anyway.

The only extra network work is a single KEX-only probe (no credentials sent) the
first time a device is seen, used to learn its key for pinning. `strict` mode
performs no probe at all — an unknown device is refused immediately.
