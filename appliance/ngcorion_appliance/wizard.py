"""
First boot: the questions asked on the console, and the one sequence that
turns the answers (or vCenter's OVF properties) into a running NGCorion.

The console is plain text on purpose: it works on every hypervisor console,
serial line and screen size, and needs nothing beyond Python.
"""
import getpass
import textwrap
from typing import Callable, List, Optional

from . import LICENSE_SERVER_HOST
from . import settings as S
from .system import CommandFailed, System, check_license_server


class Console:
    """Questions and answers on the terminal. Tests replace it with a scripted one."""

    def say(self, text: str = "") -> None:
        print(text, flush=True)

    def ask(self, prompt: str, default: Optional[str] = None) -> str:
        suffix = f" [{default}]" if default else ""
        answer = input(f"{prompt}{suffix}: ").strip()
        return answer or (default or "")

    def secret(self, prompt: str) -> str:
        return getpass.getpass(f"{prompt}: ")

    def confirm(self, prompt: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = input(f"{prompt} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes", "n", "no"):
                return answer.startswith("y")

    def choose(self, prompt: str, options: List[str], default: int = 0) -> int:
        for i, option in enumerate(options, 1):
            self.say(f"  {i}) {option}")
        while True:
            answer = self.ask(prompt, str(default + 1))
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer) - 1
            self.say(f"  Enter a number from 1 to {len(options)}.")


def ask_valid(console: Console, prompt: str, check: Callable, default: Optional[str] = None, *args):
    """Ask until the answer passes `check`; show the reason when it does not."""
    while True:
        try:
            return check(console.ask(prompt, default), *args)
        except ValueError as exc:
            console.say(f"  ! {exc}")


def ask_password(console: Console) -> str:
    while True:
        first = console.secret("Password for the web administrator 'admin'")
        try:
            S.admin_password(first)
        except ValueError as exc:
            console.say(f"  ! {exc}")
            continue
        if console.secret("The same password again") == first:
            return first
        console.say("  ! The two passwords differ.")


def ask_network(console: Console, interface: str) -> S.Network:
    if console.choose("Addressing", ["DHCP", "Static address"], 1) == 0:
        return S.Network(interface=interface, dhcp=True)
    address = ask_valid(console, "IPv4 address with prefix (e.g. 192.168.10.20/24)", S.interface_address)
    default_gw = str(next(address.network.hosts()))
    gw = ask_valid(console, "Default gateway", S.gateway, default_gw, address)
    dns = ask_valid(console, "DNS servers (comma-separated)", S.address_list, str(gw))
    return S.Network(interface=interface, dhcp=False, address=address, gateway=gw, dns=dns)


def questions(console: Console, system: System):
    """Everything the first boot needs to know. Returns (settings, admin password)."""
    nics = system.interfaces() or ["eth0"]
    interface = nics[0]
    if len(nics) > 1:
        console.say("Network interface for management:")
        interface = nics[console.choose("Interface", nics)]

    name = ask_valid(console, "Host name", S.hostname, "ngcorion")
    network = ask_network(console, interface)
    ntp = ask_valid(console, "NTP servers (comma-separated, empty: from DHCP / Ubuntu's pool)", S.server_list, "")
    password = ask_password(console)
    return S.ApplianceSettings(hostname=name, network=network, ntp=ntp), password


def summary(settings: S.ApplianceSettings) -> List[str]:
    n = settings.network
    lines = [
        f"  Host name:       {settings.hostname}",
        f"  Interface:       {n.interface}",
    ]
    if n.dhcp:
        lines.append("  Addressing:      DHCP")
    else:
        lines += [
            f"  Address:         {n.address.with_prefixlen}",
            f"  Gateway:         {n.gateway}",
            f"  DNS:             {', '.join(n.dns)}",
        ]
    lines += [
        f"  NTP:             {', '.join(settings.ntp) or 'from DHCP / default pool'}",
    ]
    return lines


def report_license_server(say: Callable[[str], None]) -> bool:
    """Check the connection to lic.ngcorion.com and say what to fix. Never stops the setup:
    the network team may still have to open the way, and NGCorion retries on its own."""
    ok, detail = check_license_server()
    if ok:
        say(textwrap.fill(f"{detail}.", width=78, initial_indent="  ", subsequent_indent="    "))
    else:
        say(textwrap.fill(f"The license server is not reachable: {detail}.", width=78,
                          initial_indent="  ! ", subsequent_indent="    "))
        say(f"    NGCorion needs {LICENSE_SERVER_HOST} on port 443 to activate and check its license.")
        say("    The setup continues; check again later from the menu.")
    return ok


def apply(system: System, settings: S.ApplianceSettings, password: str,
          say: Callable[[str], None] = print) -> None:
    """Configure the machine and bring NGCorion up. Used by the wizard and by OVF properties."""
    say("Applying network settings...")
    system.apply_network(settings.network)
    system.apply_hostname(settings.hostname)
    system.apply_ntp(settings.ntp)

    say(f"Checking the connection to the license server ({LICENSE_SERVER_HOST})...")
    report_license_server(say)

    say("Writing this installation's secrets and certificate...")
    system.ensure_env()
    system.ensure_tls_certificate(settings.hostname)

    say("Starting NGCorion (the first start applies the database schema; this takes a few minutes)...")
    system.start_stack()
    if not system.wait_healthy():
        raise CommandFailed("NGCorion did not become healthy; see 'Show the application log' in the menu")

    say("Creating the web administrator...")
    system.create_admin(password)
    system.mark_configured()


def run(console: Console, system: System) -> bool:
    """The interactive first boot. Returns True once the appliance is configured."""
    console.say("=" * 64)
    console.say(f" NGCorion {system.version()} - first start")
    console.say("=" * 64)
    console.say("A few questions set up this appliance. Nothing is changed until you confirm.")
    console.say("")
    while True:
        settings, password = questions(console, system)
        console.say("")
        console.say("Summary:")
        for line in summary(settings):
            console.say(line)
        if console.confirm("Apply these settings?"):
            break
        console.say("Starting over.\n")
    try:
        apply(system, settings, password, say=console.say)
    except CommandFailed as exc:
        console.say(f"\n  ! Setup stopped: {exc}")
        console.say("  Fix the cause and choose the first-start setup again from the menu.")
        return False
    console.say("")
    console.say("NGCorion is ready. Sign in as 'admin' with the password you chose; you will be")
    console.say("asked to set a new one at the first login.")
    for url in system.web_urls():
        console.say(f"  {url}")
    console.say("Then activate your license on the first page.")
    return True
