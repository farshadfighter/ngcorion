# Syslog

What the assets report about themselves: errors, failed sign-ins, configuration changes, interfaces going down. A message is kept only if the sender's address is the IP of an asset in the inventory.

## Set up

1. **System administrator:** the "Settings" tab → turn on "Receive syslog from the assets". In the firewall, open port 514 to NGCorion only from the device networks.
2. **On the devices** (the same examples, with NGCorion's real address, are in the "Settings" tab):

    Cisco IOS:

    ```
    logging host 10.20.9.10 transport udp port 514
    logging trap informational
    service timestamps log datetime msec
    ```

    FortiGate:

    ```
    config log syslogd setting
        set status enable
        set server "10.20.9.10"
        set port 514
    end
    ```

    Linux (rsyslog; `@@` means TCP and `@` UDP):

    ```
    *.* @@10.20.9.10:514
    ```

3. The "Sources" tab: when each device last sent a message.

## Search the messages

Filter by asset, severity (e.g. "Error or worse"), period, and search the text, app or host name. "Live" refreshes every 5 seconds and "Export CSV" gives the filtered messages (at most 50,000).

**Example:** failed SSH sign-ins in the last 24 hours: period "Last 24 hours" and search `Failed password`.

## Reported configuration changes

Configuration-change messages from Cisco (`%SYS-5-CONFIG_I`), NX-OS and FortiGate are recorded with the user name and their address, and about a minute later start an [immediate backup](/backup/schedules) (when "Back up a device when it reports a configuration change" is on).

## Alerts

"Severe syslog message" (critical or worse by default), "Asset stopped sending syslog" (after 24 hours) and, off by default, "Syslog from an address outside the inventory".

## Common problems

| Situation | Cause |
|---|---|
| A device's messages do not arrive | Its sending address is not the asset's IP; under Sources, "Addresses outside the inventory", "Assign to an asset…" makes it one of the asset's addresses (also in the asset's Network & System edit, "Other addresses") |
| "Syslog intake is on but not receiving" | Port 514 blocked by a firewall or taken; ask a system administrator |
| Low-severity messages are not kept | "Keep messages at" in Settings is set higher |

## Take care

> Syslog has no authentication and anyone on the network can send a message with a forged address; messages are never executed, and their only effect is a read-only backup (at most once every 5 minutes). Prefer TCP to UDP.

## Read more

- User guide, section 14.1 · Admin guide, section 5.6 · Training course, lesson 12.2
