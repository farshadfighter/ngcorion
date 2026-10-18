# Suggested design

A standard network design based on Cisco SAFE, sized to your network: the zones and roles a secure network should have: internet edge, DMZ, core, distribution, access and data centre. The network size (small up to 50 devices, medium 50 to 200, large over 200) comes from the number of assets. Your real assets are placed in the matching slots.

## Reading the design

- At the top: the network size, the number of assets in the inventory and how many were matched to a slot.
- Each slot holds a real asset, or says there is "no matching asset in inventory". An empty slot means the role is missing from your network, or its asset is not recorded correctly.

## Main tasks

1. Look at the empty slots: do you really lack that role (e.g. a separate DMZ or a distribution layer)?
2. If you have it, fix the type and zone of that asset in the [Asset list](/assets/inventory).
3. To plan a change, give a "Design name" and "Create this design": an editable design is created in [Design and configuration](/design-configuration).

## Take care

> The design is a reference pattern, not a verdict. A difference from it is not necessarily a weakness; review it with your network architect.

## Read more

- [Architecture validation](/architecture-validation) · User guide, section 16
