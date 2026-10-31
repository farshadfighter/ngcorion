"""
The appliance console on tty1: status and the few settings an operator needs,
with no way to a shell. systemd restarts it if it ever exits
(ngcorion-console.service), and no other terminal offers a login.
"""
from typing import Callable, List, Tuple

from . import LICENSE_SERVER_HOST
from . import settings as S
from . import wizard
from .system import CommandFailed, System


def _status(console: wizard.Console, system: System) -> None:
    console.say("=" * 64)
    hostname = (system.read("/etc/hostname") or "").strip()
    console.say(f" NGCorion {system.version()}    host: {hostname}")
    console.say("=" * 64)
    urls = system.web_urls()
    console.say(" Web interface: " + (", ".join(urls) if urls else "no network address"))
    for name, state in system.service_status() or [("NGCorion", "not running")]:
        console.say(f"   {name:<10} {state}")
    usage = system.disk_usage()
    if usage:
        used, total = usage
        console.say(f" Disk: {used / 1024 ** 3:.1f} GiB used of {total / 1024 ** 3:.1f} GiB"
                    f" ({used * 100 // max(total, 1)}%)")
    console.say("")


def _network(console, system):
    nics = system.interfaces() or ["eth0"]
    interface = nics[console.choose("Interface", nics)] if len(nics) > 1 else nics[0]
    network = wizard.ask_network(console, interface)
    if console.confirm("Apply? The web interface moves to the new address", default=False):
        system.apply_network(network)
        console.say("Network settings applied. A certificate made for the old address can be")
        console.say("replaced on the web interface (Settings > System).")


def _hostname(console, system):
    name = wizard.ask_valid(console, "Host name", S.hostname, (system.read("/etc/hostname") or "").strip())
    system.apply_hostname(name)
    console.say("Host name changed.")


def _ntp(console, system):
    servers = wizard.ask_valid(console, "NTP servers (comma-separated, empty: from DHCP / Ubuntu's pool)", S.server_list, "")
    system.apply_ntp(servers)
    console.say("NTP servers changed.")


def _license_server(console, system):
    console.say(f"Checking the connection to {LICENSE_SERVER_HOST}...")
    wizard.report_license_server(console.say)


def _grow_disk(console, system):
    console.say("After enlarging the virtual disk in the hypervisor (the machine grows it at every")
    console.say("start as well): growing the system partition and filesystem to the new size...")
    console.say("  " + system.grow_disk())


def _restart(console, system):
    if console.confirm("Restart NGCorion? Running audits are interrupted", default=False):
        system.restart_stack()
        console.say("Restarted." if system.wait_healthy(timeout=300) else "Restarted, not healthy yet.")


def _logs(console, system):
    console.say(system.logs(40))


def _reset_password(console, system):
    console.say("Sets a new password for the web user 'admin' (it must be changed at the next login).")
    password = wizard.ask_password(console)
    system.reset_admin_password(password)
    console.say("Password changed.")


def _setup(console, system):
    wizard.run(console, system)


def _reboot(console, system):
    if console.confirm("Reboot the appliance?", default=False):
        system.power("reboot")


def _poweroff(console, system):
    if console.confirm("Shut the appliance down?", default=False):
        system.power("poweroff")


def menu_items(system: System) -> List[Tuple[str, Callable]]:
    items = [
        ("Refresh status", lambda c, s: None),
        ("Network settings", _network),
        ("Host name", _hostname),
        ("NTP servers", _ntp),
        ("Check the connection to the license server", _license_server),
        ("Use the whole disk (after enlarging it)", _grow_disk),
        ("Restart NGCorion", _restart),
        ("Show the application log", _logs),
        ("Reset the web administrator's password", _reset_password),
        ("Reboot", _reboot),
        ("Shut down", _poweroff),
    ]
    if not system.configured():
        items.insert(1, ("First-start setup", _setup))
    return items


def run_once(console: wizard.Console, system: System) -> None:
    """Show the status and the menu once and perform the chosen action."""
    _status(console, system)
    items = menu_items(system)
    choice = console.choose("Choose", [label for label, _ in items])
    label, action = items[choice]
    try:
        action(console, system)
    except (CommandFailed, ValueError, OSError) as exc:
        console.say(f"  ! {label}: {exc}")
    console.say("")


def run(console: wizard.Console, system: System) -> None:
    while True:
        try:
            run_once(console, system)
        except (KeyboardInterrupt, EOFError):
            # Ctrl-C / Ctrl-D only bring the menu back; there is nothing behind it.
            console.say("")
