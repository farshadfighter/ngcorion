# Asset security requirements

The base lists you pick from when registering an asset: asset types, owners, locations, network zones, operating systems and vendors. Complete them before registering assets so every asset gets correct, consistent details.

## Tabs

| Tab | What | Example |
|---|---|---|
| Asset Type | Type with icon and category, physical or virtual | Firewall, switch, physical server, virtual server |
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

## Physical and virtual

An asset type is physical or virtual ("Runs as"). Each asset of a virtual type - a virtual server, a VM, a virtual appliance - names the physical server it runs on, and only a physical asset is offered as its host. Make two types, e.g. "Physical Server" and "Virtual Server", rather than one "Server". In the Excel file the "Virtual" column takes Yes or No.

## Why it matters

- **Network zone** feeds the risk score directly (15% weight); the Internet/public and DMZ zones count as "internet exposed" on the dashboard.
- **One list of zones:** the zones here are the ones Risk scores. Each has an exposure score from 0 to 100; a new zone left without one gets the score of an asset with no zone, so set it. An asset's zone is the same in Asset List, Risk, asset groups, alert rules and reports, wherever it was set. Changing a score recalculates the risk of the zone's assets; a zone that still has assets cannot be deleted. In the Excel file the zones sheet has a "Score" column and the assets' "Network Zone" column takes a zone's name.
- **Owner** is by default responsible for the asset's remediation items.
- **OS and vendor** are used by dynamic groups and end-of-life detection.

## Take care

> Do not delete a value assets use; edit it instead. Write names consistently ("Cisco", not sometimes "cisco systems"), or dynamic groups will miss assets.

## Read more

- [Asset list](/assets/inventory)
- User guide, section 6.1 · Training course, lesson 3.1
