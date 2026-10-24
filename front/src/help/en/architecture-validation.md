# Architecture validation

Checks the network's topology against Cisco SAFE, Cisco's reference architecture for securing a network. SAFE describes a network by its places in the network (Edge, Data Center, Campus, Branch, WAN, Cloud) and what each needs; the checks here look at the links between assets and find where the topology breaks that model: a path from the Internet or the guest network to inside hosts without a firewall, a DMZ cabled to the core, a single edge firewall, a switch every data center server depends on.

Only the topology is checked. Owners, backups and audits are covered by their own modules.

## Where the checks get their facts

- **Links:** [Topology](/topology), drawn or found over LLDP/CDP. An active link counts, a link that is down is reported, a planned one is not there yet.
- **Kind of device:** from the asset's type (firewall, switch, router, access point, server, workstation …), the same as its icon.
- **Place in the network:** from the asset's network zone. Each zone has a place (Asset Requirements, Network Zones): chosen there, or read from the zone's name ("DMZ" is the Edge, "Internal Server Zone" the Data Center, "User Network" the Campus). Besides SAFE's places, the Internet, guest networks, the management network and labs are kept apart because the checks need them.

A path is "unfiltered" when it leads from one place to another over active links without passing a firewall.

## The checks

| Domain | Check | Severity |
|---|---|---|
| Segmentation | Reachable from the Internet without a firewall | High |
| Segmentation | The DMZ reaches the inside without a firewall | High |
| Segmentation | The guest network reaches other networks without a firewall | High |
| Management | The management network is reachable without a firewall | High |
| Segmentation | Users reach the data center without a firewall | Medium |
| Segmentation | A lab network is connected to production without a firewall | Medium |
| Segmentation | Server in the Internet zone / in a user or guest network; user device in the data center or DMZ | High–Low |
| Threat defense | Only one edge firewall | Medium |
| Availability | Only one Internet connection | Medium |
| Availability | Single point of failure (for critical or data center assets: high) | High/Medium |
| Availability | Server or critical asset connected to a single device; network device with a single uplink; link down | High–Low |
| Visibility | Network device or server not in the topology; place in the network unknown | Low |

"What is checked" on the page lists every check with its recommendation.

## Main tasks

1. "Run Analysis" checks the current topology.
2. The findings are grouped by check: the recommendation once, then each asset with what the topology shows - the unfiltered path (`guest-ap-1 → core-sw-1 → dc-sw-1 → app-02`), the only link, the assets cut off when a device fails.
3. For each finding, one of:
    - **Fix:** change the network (or correct the topology or the zone) and analyse again; the finding disappears.
    - **"Accept":** you knowingly accept the risk; it moves to "Accepted".
    - **"Ignore":** it does not apply to you; with a reason.

Open findings also go to [Remediation](/remediation).

## Example

"The DMZ reaches the inside without a firewall" for `app-02`, path `dmz-sw → core-sw-1 → dc-sw-1 → app-02`: the DMZ switch is cabled to the core switch. A public server that is broken into reaches the application server directly. Remove the link, or route it through the firewall; analyse again and the finding is gone.

## Take care

> The checks are as good as the topology and the zones. Set up LLDP/CDP so links are found, give every asset its zone, and check each zone's place in the network; an asset whose place is unknown is reported and left out of the segmentation checks.

## Read more

- [Network zones](/assets/requirements) · [Topology](/topology) · [Suggested design](/design-suggestion) · User guide, section 16
