"""
NGCorion appliance: the first-boot wizard and the console menu of the virtual
appliance (OVA / qcow2 / VHDX built by appliance/build.sh).

Runs on the appliance's own OS (Ubuntu 24.04 LTS, Python 3.12), standard
library only. Nothing here is imported by the NGCorion application itself.

    python3 -m ngcorion_appliance console     # tty1: wizard on first boot, then the menu
    python3 -m ngcorion_appliance apply-ovf   # non-interactive, from vCenter OVF properties

Modules:
    settings  - what the operator chooses, and its validation
    render    - the configuration files those choices become
    ovf       - reading OVF properties set in vCenter (guestinfo.ovfEnv)
    system    - applying a configuration to the machine (files + commands)
    wizard    - the first-boot questions
    console   - the menu shown on the console afterwards (no shell)
"""

APPLIANCE_DIR = "/opt/ngcorion"
STATE_DIR = "/var/lib/ngcorion-appliance"
