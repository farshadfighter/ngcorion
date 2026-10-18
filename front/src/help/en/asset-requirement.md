# Asset security requirements

The base lists you pick from when registering an asset: asset types, owners, locations, network zones, operating systems and vendors. Complete them before registering assets so every asset gets correct, consistent details.

## Tabs

| Tab | What | Example |
|---|---|---|
| Asset Type | Type with icon and category | Firewall, switch, server, camera |
| Owners | Name, department, role, email and phone of who is responsible | "Network team" |
| Location | Site, floor, room, rack and unit | HQ / 3 / Server room / A2 |
| Network Zone | Zones and the risk score of each | Internal, DMZ, card data environment |
| OS Catalog | Name, version and vendor | Ubuntu 22.04 |
| Vendors | Name and type (hardware, software) | Cisco, Fortinet |
| Others | Statuses, confidentiality levels and risk levels | System-defined; cannot be changed |

## Main tasks

1. **Add one:** in its tab, the "+ Add …" button (e.g. "+ Add Owner"), fill in the form and "Create".
2. **Import many:** "Download Template" → fill in the Excel file → "Import".
3. **Back up or move:** "Export" gives every list in one file.
4. **Delete several:** tick the rows and "Delete selected".

## Why it matters

- **Network zone** feeds the risk score directly (15% weight); the Internet/public and DMZ zones count as "internet exposed" on the dashboard.
- **Owner** is by default responsible for the asset's remediation items.
- **OS and vendor** are used by dynamic groups and end-of-life detection.

## Take care

> Do not delete a value assets use; edit it instead. Write names consistently ("Cisco", not sometimes "cisco systems"), or dynamic groups will miss assets.

## Read more

- [Asset list](/assets/inventory)
- User guide, section 6.1 · Training course, lesson 3.1
