# License

The license is by **number of assets** (a base plan plus 50-asset add-on packs) and is bound to **one machine**. This page shows the plan, the asset limit and count, the expiry date and the last contact with the license server. System administrators only.

## Online activation

Enter the license key and click "Activate". The license server's answer is checked by its digital signature. After that, NGCorion contacts the license server every hour.

## Offline activation

1. "No internet access? Offline activation" → license key → "Download the request file" (`.ngcreq`).
2. Send it to the license administrator by the organisation's approved route.
3. Install the signed file that comes back (`.ngclic`) with "Upload license file". It is valid for at most one year; repeat these steps before it ends.

## If the license server cannot be reached

| Time | State |
|---|---|
| Up to 48 hours | Normal |
| After that, up to 30 days | Pilot license (5 assets) |
| After 30 days | Locked; the full plan returns as soon as contact is back |

Check DNS, outbound port 443 and the proxy. Turning the server clock back does not lengthen these periods; it invalidates the license.

## Asset limit

Above the limit, no new asset can be added. If there are more assets than the limit, audits and hardening run only on the oldest assets up to the limit, and the rest are shown "Outside license".

## Take care

> A new virtual machine has a different fingerprint; before activating on it, ask the license administrator to release the license from the old machine. Turn on the "License problem" alert for yourself.

## Read more

- Admin guide, section 6 · Training course, lesson 2.1
