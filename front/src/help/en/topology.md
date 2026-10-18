# Topology

A map of the real assets and the links between them, with port, speed and VLAN. Most links are drawn on their own from the devices' own LLDP/CDP neighbour tables; you can also draw links by hand. The NOC shows the live state of this same map.

## Tabs

- **"Map":** drag devices to move them (the layout is saved). To draw a link, drag from one device's port to another's. Click a link for its "Link details" (type, status, speed, VLAN, subnet and origin).
- **"Neighbours (LLDP/CDP)":** every neighbour the devices reported, with the ports at both ends, capabilities, management address and when it was last seen. Inner tabs: "On the map", "Not on the map", "Not in the inventory", "Removed from the map", "Devices read" and "Settings".

## Links found automatically

1. Turn on LLDP on the devices (Cisco: `lldp run`; CDP is on by default. FortiGate: `set lldp-transmission enable` on the ports).
2. The devices need an SNMP credential ([Hosts](/noc/hosts)).
3. "Neighbours (LLDP/CDP)" → "Read now" (automatically every 60 minutes).
4. Add a neighbour that is not an asset (e.g. an access point) from "Not in the inventory".

## Reading the map

| Sign | Meaning |
|---|---|
| Solid line | Drawn by hand or found by LLDP/CDP |
| Dashed | Planned, or a hosted VM |
| Red and dashed | The devices no longer report the link: a cable unplugged or moved |

A lost link raises "Network link lost" and is removed after 30 days.

## Other tasks

- **"Remove from map":** a discovered link you do not want; it is not drawn again until "Add to map".
- **"Validate":** a quick structural check of this map; for the full check, [Architecture validation](/architecture-validation).

## Take care

> Links you drew by hand are never changed automatically; they only become "confirmed". A device that cannot be read never makes a link look lost.

## Read more

- User guide, sections 16 and 16.1 · Training course, lesson 12.4
