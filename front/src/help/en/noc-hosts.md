# Hosts

Every asset with its SNMP monitoring status, CPU, memory and disk use, and the time of the last poll. Click an asset for its host page: system info, device health, interfaces, history and the SNMP credential.

## Start monitoring a device

1. **On the device:** create a read-only SNMP user. A Cisco example with SNMP v3:

    ```
    snmp-server group NGC-RO v3 priv
    snmp-server user ngc-mon NGC-RO v3 auth sha <auth-password> priv aes 128 <priv-password>
    ```

2. **In NGCorion:** the host page → "SNMP Credential": version v3, user name `ngc-mon`, "Auth Protocol" SHA, "Priv Protocol" AES and the keys → "Save".
3. "Poll Now".

SNMP credentials are stored encrypted. Prefer v3 with Auth and Priv over v2c (a community string).

## The host page

| Section | What |
|---|---|
| System Info | Name, OS/firmware, location and contact as the device reports them |
| Device health | CPU, memory, the fullest file system, the hottest temperature sensor and uptime |
| Interfaces | Status, speed and in/out traffic of each port |
| History | Reachability, traffic and health charts for any period |

If the device stops answering, the last reported values stay with a note. A device restart is detected and raises the alert "Device restarted".

## Storage

"Storage" above the list shows what syslog messages and SNMP metrics take against their disk space, and the free space on the server's disk. When a store passes its limit, its oldest data is removed first. A system administrator sets how long SNMP metrics are kept - raw samples in hours, 5-minute, hourly and daily averages in days (0 = for good) - and the disk space they may take; the syslog limits are in Syslog, Settings.

## Health alerts

"CPU usage high" and "Memory usage high" (every poll in a window at 90% or more), "Disk almost full" (90%) and "Temperature high" (70 °C). Thresholds are changed in the [notification rules](/settings/notifications).

## Common problems

| Situation | Cause |
|---|---|
| "Unreachable" with correct credentials | A firewall does not let UDP 161 in from NGCorion |
| System info is empty | The device does not expose the MIB-2 system group over SNMP |
| Linux health is empty | The default net-snmp view is closed; add HOST-RESOURCES and UCD |
| No temperature | A virtual machine has no temperature sensor |

## Read more

- [Unknown devices](/noc/unknown-devices) · [Topology](/topology) (both use the same SNMP credentials)
- User guide, section 14 · Training course, lesson 12.1
