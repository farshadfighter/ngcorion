# Network status (NOC)

The live SNMP status of every asset, on the same graph as Topology, coloured by reachability: which device is up, which is down, and which is not monitored at all.

## Cards

| Card | Meaning |
|---|---|
| Reachable / Unreachable | The result of the latest SNMP poll |
| Not Monitored | Assets without an SNMP credential |
| Unknown devices | Devices on the network that are not assets, with the number of new ones |

## Main tasks

- **"Poll All Now":** polls every device right away.
- Click a device to open its [host](/noc/hosts) page with health, interfaces and history.
- Bring **"Not Monitored"** down: give important devices an "SNMP Credential" on their host page.

## Take care

> A device without an SNMP credential raises no "Device unreachable" alert. Vital devices (firewall, core switch) must be monitored.

## Read more

- [Hosts](/noc/hosts) · [Topology](/topology)
- User guide, section 14 · Training course, lesson 12.1
