"""
The appliance console on tty1: status and the few settings an operator needs,
with no way to a shell. systemd restarts it if it ever exits
(ngcorion-console.service), and no other terminal offers a login.
"""
from typing import Callable, List, Optional, Tuple

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
    _ssh_status(console, system)
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


def _ssh_status(console, system):
    access = system.ssh_access()
    if not access.enabled:
        console.say(" SSH: off")
        return access
    how = " and ".join(x for x in ("password" if access.password else "",
                                   f"{len(access.keys)} key(s)" if access.keys else "") if x)
    console.say(f" SSH: on ({'running' if system.ssh_running() else 'NOT running'}), user "
                f"'{S.SSH_USER}', sign-in with {how}, from "
                + (", ".join(access.sources) if access.sources else "any address"))
    return access


def _ask_ssh_keys(console, current):
    keys = list(current)
    if keys and not console.confirm(f"Keep the {len(keys)} public key(s) already allowed?", default=True):
        keys = []
    console.say("Public keys allowed to sign in, one line each (e.g. the content of id_ed25519.pub);")
    console.say("an empty line when done.")
    while True:
        line = console.ask("Public key (empty: done)")
        if not line:
            return keys
        try:
            key = S.ssh_public_key(line)
        except ValueError as exc:
            console.say(f"  ! {exc}")
            continue
        if key.split()[1] not in [k.split()[1] for k in keys]:
            keys.append(key)
        console.say(f"  Added ({len(keys)} key(s)).")


def _ask_ssh_password(console):
    while True:
        first = console.secret(f"Password for the SSH user '{S.SSH_USER}'")
        try:
            S.ssh_password(first)
        except ValueError as exc:
            console.say(f"  ! {exc}")
            continue
        if console.secret("The same password again") == first:
            return first
        console.say("  ! The two passwords differ.")


def _ssh(console, system):
    """SSH to this same menu (only from the hypervisor console: over SSH it is not offered)."""
    console.say("SSH gives the same menu as this console, nothing more: no shell, no file copy,")
    console.say("no tunnels. Every sign-in and every action is recorded in the system log.")
    access = _ssh_status(console, system)
    options = ["Turn SSH on / change its settings", "Turn SSH off", "Back"]
    choice = console.choose("SSH", options, 2)
    if choice == 2:
        return
    if choice == 1:
        if console.confirm("Turn SSH off?", default=False):
            system.disable_ssh()
            _log(system, "SSH turned off")
            console.say("SSH is off.")
        return

    keys = _ask_ssh_keys(console, access.keys)
    if keys:
        use_password = console.confirm("Also allow signing in with a password?", default=access.password)
    else:
        console.say("No key: sign-in with a password.")
        use_password = True
    password = None
    if use_password and (not access.password or console.confirm("Set a new password?", default=False)):
        password = _ask_ssh_password(console)
    sources = wizard.ask_valid(
        console, "Accept SSH only from (addresses or networks, comma-separated; empty: any)",
        S.ssh_sources, ", ".join(access.sources))
    new = S.SshAccess(enabled=True, password=use_password, keys=keys, sources=sources).check()
    console.say(f"  User '{S.SSH_USER}', port 22, sign-in with "
                + " and ".join(x for x in ("password" if use_password else "",
                                           f"{len(keys)} key(s)" if keys else "") if x)
                + ", from " + (", ".join(sources) if sources else "any address"))
    if not console.confirm("Apply?", default=True):
        return
    system.apply_ssh(new, password)
    _log(system, "SSH turned on or changed (password %s, %d key(s), from %s)" % (
        "allowed" if use_password else "not allowed", len(keys), ", ".join(sources) or "any address"))
    console.say("SSH is on. Host key fingerprints (compare them on the first connection):")
    for line in system.ssh_host_fingerprints():
        console.say("  " + line)
    for url in system.web_urls():
        console.say(f"  ssh {S.SSH_USER}@{url.split('//')[1].rstrip('/')}")


def _setup(console, system):
    wizard.run(console, system)


def _reboot(console, system):
    if console.confirm("Reboot the appliance?", default=False):
        system.power("reboot")


def _poweroff(console, system):
    if console.confirm("Shut the appliance down?", default=False):
        system.power("poweroff")


class _LogOut(Exception):
    """The SSH user chose to end the session."""


def _log_out(console, system):
    raise _LogOut()


def _log(system: System, action: str, origin: str = "console") -> None:
    """Record an action of the menu in the system log (journal; facility auth)."""
    try:
        import syslog
        syslog.openlog("ngcorion-console", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, f"{origin}: {action}")
    except Exception:
        pass


def menu_items(system: System, ssh: bool = False) -> List[Tuple[str, Callable]]:
    """The menu. Over SSH (ssh=True): no first-start setup and no SSH settings (both only on the
    hypervisor console), and a way to end the session."""
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
    if ssh:
        items.append(("Log out", _log_out))
        return items
    items.insert(items.index(("Use the whole disk (after enlarging it)", _grow_disk)) + 1,
                 ("SSH access", _ssh))
    if not system.configured():
        items.insert(1, ("First-start setup", _setup))
    return items


def run_once(console: wizard.Console, system: System, origin: Optional[str] = None) -> None:
    """Show the status and the menu once and perform the chosen action. `origin` is set over
    SSH ("ssh from <address>"): the SSH menu, and every action is recorded with it."""
    _status(console, system)
    items = menu_items(system, ssh=origin is not None)
    choice = console.choose("Choose", [label for label, _ in items])
    label, action = items[choice]
    if label != "Refresh status":
        _log(system, label, origin or "console")
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


def run_ssh(console: wizard.Console, system: System, client: str) -> None:
    """The SSH session (sshd ForceCommand, through sudo): the menu until the user logs out or the
    connection ends (Ctrl-D, Ctrl-C). When it returns, the session is over; there is no shell."""
    origin = f"ssh from {client or 'unknown'}"
    _log(system, "session started", origin)
    try:
        while True:
            run_once(console, system, origin)
    except (_LogOut, KeyboardInterrupt, EOFError):
        pass
    finally:
        _log(system, "session ended", origin)
