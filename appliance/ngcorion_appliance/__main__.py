"""
Entry point on the appliance (ngcorion-console.service runs it on tty1).

    python3 -m ngcorion_appliance console

On a machine that is not configured yet it first looks for vCenter OVF
properties and, when they are complete, configures itself unattended;
otherwise the first-start questions are asked. Then the console menu.
"""
import sys

from . import console, ovf, wizard
from .system import CommandFailed, System


def first_boot(con: wizard.Console, system: System) -> None:
    document = ovf.read_environment()
    props = ovf.parse(document) if document else {}
    if ovf.complete(props):
        con.say("Configuring from the OVF properties set in vCenter...")
        try:
            nics = system.interfaces() or ["eth0"]
            settings, password = ovf.to_settings(props, nics[0])
            wizard.apply(system, settings, password,
                         license_fingerprint=props.get("ngcorion.license_server_sha256", ""),
                         say=con.say)
            con.say("Configured from the OVF properties.")
            return
        except (CommandFailed, ValueError) as exc:
            con.say(f"  ! The OVF properties could not be applied: {exc}")
            con.say("  Continuing with the questions on this console.\n")
    while not wizard.run(con, system):
        if not con.confirm("Run the first-start setup again?"):
            return


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    command = args[0] if args else "console"
    if command != "console":
        print("usage: python3 -m ngcorion_appliance console", file=sys.stderr)
        return 2
    con, system = wizard.Console(), System()
    if not system.configured():
        try:
            first_boot(con, system)
        except (KeyboardInterrupt, EOFError):
            con.say("")
    console.run(con, system)
    return 0


if __name__ == "__main__":
    sys.exit(main())
