# Unknown devices

Devices working on the network that are not in the asset inventory. NGCorion does not scan the network: it only reads the ARP table (IP to MAC) of routers and firewalls and the MAC table (which MAC is behind which port) of switches that have an SNMP credential; every 15 minutes by default.

## Columns

| Column | What |
|---|---|
| Device | Guessed kind (IP camera, IP phone, UPS, PLC, computer, virtual machine …) and the maker from the MAC prefix |
| Address | MAC and IP |
| Seen on | The reporting device, port and VLAN, and whether it came from the ARP or MAC table |
| First and last seen | — |

A random MAC (phones and laptops on Wi-Fi) is shown as a private (random) address, without a maker.

## Main tasks

- **"Add as asset":** IP address, MAC and maker are filled in; the default name comes from the kind and the end of the MAC (e.g. `camera-8899`). It counts towards the license.
- **"Ignore":** for devices that should not become assets (guest network, lab), with a note. They raise no alert; "Stop ignoring" puts them back.
- **"Read now":** reads the tables right away.

## Tabs

"Unknown devices", "New" (last 24 hours), "Ignored", "In the inventory", "Devices read" (each router/switch's result and error) and "Settings".

## Example

| Device | Action |
|---|---|
| A Hikvision MAC on `acc-sw-01` port `Gi1/0/14`, VLAN 30 | An IP camera; "Add as asset" |
| A random MAC on the guest VLAN | "Ignore" with the note "guest Wi-Fi" |
| A Dell computer on a meeting-room port | Ask its department; if not allowed, shut the port |

## Alert

"New device on the network" when a MAC that is not an asset is seen for the first time. What the first read of each router/switch finds is the baseline and raises no alert; more than 10 at once raise one "New devices on the network" alert.

## Take care

> For full coverage, give the router/firewall of each network (ARP table) and the access switches (MAC table) an SNMP credential. A table that cannot be read shows its error under "Devices read"; usually a restricted SNMP view (Admin guide, section 5.7).

## Read more

- [Hosts](/noc/hosts)
- User guide, section 14.2 · Training course, lesson 12.3
