# Design and configuration

Draw the future network, with versions: which devices, where, with which links. Each design has separate versions so options can be compared side by side.

## Make a design

1. "New Design" → a name (e.g. "North branch refresh") → **"Start from":** "Blank canvas" or a **network size** (the base from the [Suggested design](/design-suggestion)).
2. Or "Create this design" on the Suggested design page.
3. **Templates (Cisco SAFE):** "Enterprise Campus", "Data Center with SAN" (a firewall and switch pair, hypervisors on both, storage on two SAN fabrics A and B, a management network with a jump host) and "Branch with WAN" (MPLS and LTE on one router, SD-WAN and the Internet on the other, a branch firewall pair, dual-homed switches).

## Work on a design

- **A new version:** "New Version" → "Start empty" or clone from an earlier version, with notes.
- **Device:** "Add device" → type and label. A planned device is dashed; mapped to a real asset, it is drawn with that asset's icon.
- **Link:** drag from one device to another; set the VLAN and subnet on the link.
- **External networks:** the "External" group of "Add device" has the Internet, MPLS, WAN, SD-WAN, LTE/4G, public cloud and partner network; connect them to the routers or firewalls that end them.

## Example

"North branch refresh": version 1 with one core switch; version 2 with two core switches and a redundant link to the firewall. Show both to the change board and, after the work, map the planned devices to the real assets.

## Take care

> A design changes nothing on the real network; it is only a plan. The real network is in [Topology](/topology).

## Read more

- User guide, section 16
