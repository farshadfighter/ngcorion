# Auto discovery

Scans the network with nmap to find hosts, open ports and services. Each host found can become a new asset or update an existing one. Open ports also feed the risk score and the TLS certificate scan.

## Run a scan

1. "New Scan".
2. **Scan name** and **target IP or range:** one address (`10.20.1.10`), a network (`10.20.1.0/24`) or a range (`10.20.1.1-254`).
3. **Scan type:**

    | Type | Ports | Time |
    |---|---|---|
    | Well-known ports | 1 to 1024 plus common database and application ports | Fast |
    | All ports | 1 to 65535 | Slow |
    | Custom ports | Only the ports you list | Depends |

4. **Protocol:** TCP, UDP or both. "Enable Service Version Detection (-sV)" also reads service names and versions, but is slower.
5. "Start Scan". Progress shows in the "Activity Log".

## After the scan

1. In the history, "View results" lists the hosts with their ports and services.
2. **A new host:** "Approve" and choose an asset type; for several at once, "Bulk Approve".
3. **A host that is already an asset:** "Apply Discovery" → the matching asset (suggested by IP, MAC or name) → a mode:
    - **Merge / Update:** only empty fields are filled and new ports added (recommended).
    - **Overwrite:** all earlier details and ports are replaced by the scan result.
4. Reject a host you do not want (e.g. a guest laptop) with "Reject host".

## Example

Scan "Linux servers" on `10.20.1.0/24` with well-known ports: host `10.20.1.35` with ports 22 and 443 is found and is not an asset. "Approve" it as a server, then complete its name, owner and zone in the [Asset list](/assets/inventory).

## Take care

> Scan only networks you are allowed to scan. An "All ports" scan of a large network takes hours and an IPS on the way may take it for an attack; agree it with the network team first. "Overwrite" removes details you entered by hand.

## Common problems

| Situation | Cause |
|---|---|
| "nmap is not installed on the server" | Incomplete installation; contact the system administrator. |
| No host found | A firewall between NGCorion and that network, or the hosts are off. |
| The scan "Timed Out" | The range is large; make it smaller or use well-known ports. |

## Read more

- [Discovery schedules](/assets/schedule-discovery)
- User guide, section 6.3 · Training course, lesson 3.4
