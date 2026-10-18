# API keys

Other systems (SIEM, CMDB, scripts) call the API with a key, not with a person's account. Each key has **its own account** with only the key's access, and everything it does is recorded under that account in the audit trail. System administrators only.

## Create a key

1. "New API key".
2. **Name** (e.g. `siem-wazuh`) and description: which system uses it and who owns it.
3. **Valid until:** 90 days by default, 365 at most.
4. **Access:** for each area "None", "Read" or "Read and write". Only what that system needs.
5. **"Allowed addresses (optional)":** one address or network per line; empty means any address.
6. "Create the key". The token (`ngk_…`) is shown **only this once**; put it straight into the target system's secret store and click "I have stored it".

## Use

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "https://ngcorion.corp.example/api/cve/findings"
```

| Response | Meaning |
|---|---|
| 401 `Invalid API key` | Wrong, unknown or revoked token |
| 401 `API key has expired` | The key's end date has passed |
| 403 | Address not allowed, or the key has no access to that area |

## What a key never gets

User management and credential profiles never; hardening, device backups, system settings and logs read only; a key never deletes and is never a system administrator. So a leaked key cannot change the network's configuration.

## Renew and revoke

- **"Renew the secret":** a new token; the old one stops working at once. Do it when someone who saw the token leaves.
- **"Revoke for good":** the key stops working forever; its account stays for the records.
- Turn on the alert "API key expires soon" (14 days before the end by default) for the owner of that system.

## Take care

> Every three months, look at each key's "Last used" and revoke unused keys. Behind a proxy, the address NGCorion sees is the proxy's.

## Read more

- Admin guide, section 7.7 · Training course, lesson 16
