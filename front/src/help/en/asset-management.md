# Assets overview

The state of the inventory: how many assets there are and how many were added lately, which details are missing, how much of the inventory the other modules cover, and its mix by type, vendor, operating system, status and zone. Every figure, row and bar opens the [Asset list](/assets/inventory) already filtered to the assets it counts.

## Figures

| Figure | Meaning |
|---|---|
| Assets in the inventory | Every registered asset |
| Added in the last 7 / 30 days | Assets added in that time; opens the list of them |
| License use | Assets in the inventory against the assets the license covers |
| Unknown devices on the network | Devices NOC saw in ARP and MAC tables that are not assets, with how many are new this week (needs NOC access) |

## Missing details

Each card counts the assets without an owner, an IP address, an operating system or a location, and opens the list of them. "Network zone not chosen (risk uses a default)" counts assets whose risk zone was never set, so the risk score assumes one; set it on [Risk of assets](/risk/assets). A green card means nothing is missing.

> Missing details weaken everything built on them: dynamic groups, end-of-life tracking, CVE matching and the risk score. Clear these cards first.

## Coverage

| Figure | Meaning |
|---|---|
| Audited in the last 90 days | Assets audited in that time, of all assets |
| Configuration backed up in the last 30 days | Devices with a recent backup, of the devices that can be backed up |
| Monitored over SNMP | Assets with SNMP settings, of all assets |
| End-of-life status known | Assets whose software was matched to the end-of-life catalog |

Each figure needs read access to its own module; the bar is green from 80%, yellow from 50%.

## The filtered asset list

The list shows the filter as a chip above the table, for example "No owner" or "Vendor: Fortinet"; click the chip to remove it. The filters can be typed in the address too:

```
/assets/inventory?missing=owner
/assets/inventory?type=3&vendor=Fortinet
/assets/inventory?added=7
```

`missing` takes owner, ip, os or location; `status` takes active, standby, inactive, unknown or decommissioned.

## Read more

- [Asset list](/assets/inventory) · [Asset groups](/assets/groups) · [Auto discovery](/assets/discovery) · [Unknown devices](/noc/unknown-devices)
- User guide, section 6
