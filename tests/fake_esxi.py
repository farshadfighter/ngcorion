"""
A small ESXi command emulator for tests: `esxcli`, `vim-cmd`, `chkconfig`,
`vmware` and the /etc/init.d service scripts, answering in esxcli's text
formats from a JSON state file ($FAKE_ESXI_STATE) and changing that state
on set/enable/disable commands. It lets the ESXi module's real shell
scripts (awk, sed, loops) run under busybox sh, as on a host, without one.

Only the commands the module uses are emulated; anything else exits 1 the
way esxcli does for an unknown namespace. The initial state (`initial()`)
matches tests/esxi_sample.py.

    python3 fake_esxi.py <tool> [args...]
"""
import json
import os
import sys

from esxi_sample import HARDENED_VMX, INT_OPTIONS, STRING_OPTIONS


def initial(root: str) -> dict:
    adv = {p: {"type": "integer", "int": v, "default_int": v} for p, v in INT_OPTIONS.items()}
    adv.update({p: {"type": "string", "str": v, "default_str": v} for p, v in STRING_OPTIONS.items()})
    adv["/Net/DVFilterBindIpAddress"]["default_str"] = ""
    rulesets = {"sshServer": True, "sshClient": False, "nfsClient": False, "dhcp": True, "dns": True, "snmp": False,
                "ntpClient": False, "CIMHttpServer": True, "CIMHttpsServer": True, "CIMSLP": False,
                "vSphereClient": True, "webAccess": True, "syslog": False, "vMotion": True}
    policy = {"Allow Promiscuous": False, "Allow MAC Address Changes": False, "Allow Forged Transmits": False}
    loose = {"Allow Promiscuous": False, "Allow MAC Address Changes": True, "Allow Forged Transmits": True}
    vms = [
        {"id": 1, "name": "db01", "ds": "datastore1", "path": "db01/db01.vmx", "lines": HARDENED_VMX},
        {"id": 2, "name": "web01", "ds": "datastore1", "path": "web01/web01.vmx",
         "lines": ['tools.guestlib.enableHostInfo = "FALSE"', 'scsi0:0.mode = "persistent"']},
        {"id": 3, "name": "lab-nested", "ds": "datastore2", "path": "lab-nested/lab-nested.vmx",
         "lines": ['usb.present = "TRUE"', 'serial0.present = "TRUE"', 'scsi0:1.mode = "independent-nonpersistent"',
                   'isolation.tools.copy.disable = "FALSE"', 'pciPassthru0.present = "TRUE"']},
    ]
    for vm in vms:
        path = os.path.join(root, "vmfs/volumes", vm["ds"], vm["path"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            # Lines the collector must never read: a guestinfo secret, the display name, the UUID.
            f.write("\n".join([f'displayName = "{vm["name"]}"', 'guestinfo.ovfEnv.password = "Guest-Secret-7"',
                               'uuid.bios = "42 1a 2b 3c"'] + vm["lines"]) + "\r\n")
    keys = os.path.join(root, "etc/ssh/keys-root/authorized_keys")
    os.makedirs(os.path.dirname(keys), exist_ok=True)
    with open(keys, "w") as f:
        f.write("# root keys\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyOnly ops@jump01\n")
    return {
        "version": "VMware ESXi 8.0.2 build-22380479", "release": "VMware ESXi 8.0 Update 2",
        "adv": adv,
        "services": {"SSH": ["on", True], "ESXShell": ["off", False], "slpd": ["off", False],
                     "sfcbd-watchdog": ["on", True], "snmpd": ["off", False], "ntpd": ["off", False]},
        "ntp": {"enabled": False, "servers": []},
        "coredump": {"enabled": False, "vnic": "", "ip": "", "port": 0},
        "firewall": {"enabled": True, "default_action": "DROP",
                     "rulesets": {n: {"enabled": e, "all": n not in ("sshServer", "vMotion"),
                                      "ips": [] if n not in ("sshServer", "vMotion") else ["10.10.0.0/24"]}
                                  for n, e in rulesets.items()}},
        "snmp": {"enable": False, "communities": ""},
        "acceptance": "PartnerSupported",
        "vibs": [["esx-base", "8.0.2-0.0.22380479", "VMware", "VMwareCertified"],
                 ["vsan", "8.0.2-0.0.22380479", "VMware", "VMwareCertified"],
                 ["lsi-mr3", "7.727.02.00-1OEM.800.1.0.20613240", "BCM", "VMwareCertified"],
                 ["nvidia-vgpu", "535.104.06-1OEM.800.1.0.20613240", "NVD", "PartnerSupported"],
                 ["net-usbnic", "1.12-2vmw.800.1.0.20613240", "VFrontDe", "CommunitySupported"]],
        "encryption": {"mode": "NONE", "exec": False, "secure_boot": False},
        "fips": {"ssh": True, "rhttpproxy": True},
        "lockdown": "lockdownDisabled",
        "accounts": [["root", "Administrator"], ["dcui", "DCUI User"],
                     ["vpxuser", "VMware VirtualCenter administration account"], ["opsadmin", "Operations"]],
        "vswitches": {"vSwitch0": dict(policy), "vSwitch1": dict(loose)},
        "portgroups": [
            {"name": "Management Network", "vswitch": "vSwitch0", "clients": 1, "vlan": 0, "policy": dict(policy)},
            {"name": "VM Network", "vswitch": "vSwitch0", "clients": 2, "vlan": 20, "policy": dict(policy)},
            {"name": "Backup Network", "vswitch": "vSwitch1", "clients": 1, "vlan": 30, "policy": dict(loose)},
            {"name": "Trunk-Monitor", "vswitch": "vSwitch1", "clients": 1, "vlan": 4095,
             "policy": {**loose, "Allow Promiscuous": True}},
        ],
        "iscsi": {"vmhba64": {"uni": "prohibited", "mutual": "prohibited"}},
        "vms": [{k: v for k, v in vm.items() if k != "lines"} for vm in vms],
    }


def b(v) -> str:
    return "true" if v else "false"


def truthy(v) -> bool:
    return str(v).lower() in ("true", "t", "1", "yes")


class Fail(Exception):
    pass


def parse(args):
    words, opts, i = [], {}, 0
    while i < len(args) and not args[i].startswith("-"):
        words.append(args[i])
        i += 1
    while i < len(args):
        a = args[i]
        if a.startswith("--") and "=" in a:
            k, v = a[2:].split("=", 1)
        elif i + 1 < len(args) and not args[i + 1].startswith("-"):
            k, v = a.lstrip("-"), args[i + 1]
            i += 1
        else:
            k, v = a.lstrip("-"), True
        opts.setdefault(k, []).append(v)
        i += 1
    return " ".join(words), {k: v[-1] for k, v in opts.items()}, opts


def table(headers, rows):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    out = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)), "  ".join("-" * w for w in widths)]
    out += ["  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    return "\n".join(out)


def kv(pairs):
    return "\n".join(f"   {k}: {v}" for k, v in pairs)


def policy_text(p):
    return kv((k, b(p[k])) for k in ("Allow Promiscuous", "Allow MAC Address Changes", "Allow Forged Transmits"))


def set_policy(p, o):
    for opt, key in (("allow-promiscuous", "Allow Promiscuous"), ("allow-mac-change", "Allow MAC Address Changes"),
                     ("allow-forged-transmits", "Allow Forged Transmits")):
        if opt in o:
            p[key] = truthy(o[opt])


def esxcli(s, args):  # noqa: C901 - one branch per emulated command
    cmd, o, multi = parse(args)
    if cmd == "system settings advanced list":
        path = o.get("o")
        a = s["adv"].get(path)
        if a is None:
            raise Fail(f"Unable to find option {path.split('/')[-1] if path else ''}")
        is_int = a["type"] == "integer"
        return kv([("Path", path), ("Type", a["type"]), ("Int Value", a.get("int", 0) if is_int else 0),
                   ("Default Int Value", a.get("default_int", 0) if is_int else 0), ("Min Value", 0),
                   ("Max Value", 99999), ("String Value", "" if is_int else a["str"]),
                   ("Default String Value", "" if is_int else a.get("default_str", "")), ("Valid Characters", ""),
                   ("Description", "emulated option")])
    if cmd == "system settings advanced set":
        a = s["adv"].get(o.get("o"))
        if a is None:
            raise Fail("Unable to find option")
        if "d" in o:
            if a["type"] == "integer":
                a["int"] = a["default_int"]
            else:
                a["str"] = a.get("default_str", "")
        elif "i" in o:
            if a["type"] != "integer":
                raise Fail("Invalid type: option is a string")
            a["int"] = int(o["i"])
        elif "s" in o:
            if a["type"] != "string":
                raise Fail("Invalid type: option is an integer")
            a["str"] = o["s"]
        return ""
    if cmd == "system ntp get":
        return kv([("Enabled", b(s["ntp"]["enabled"])), ("Loglevel", "warning"),
                   ("Server", ", ".join(s["ntp"]["servers"]))])
    if cmd == "system ntp set":
        if "s" in multi:
            s["ntp"]["servers"] = multi["s"]
        if "e" in o:
            s["ntp"]["enabled"] = truthy(o["e"])
            s["services"]["ntpd"] = ["on", True] if s["ntp"]["enabled"] else ["off", False]
        return ""
    if cmd == "system syslog config get":
        lh = s["adv"]["/Syslog/global/logHost"]["str"]
        return kv([("Check Certificate Revocation", "false"), ("Default Network Retry Timeout", 180),
                   ("Enforce SSLCertificates", "true"), ("Local Log Output", "/scratch/log"),
                   ("Local Log Output Is Configured", "false"), ("Local Log Output Is Persistent", "true"),
                   ("Log Level", "error"), ("Log Filtering", "false"), ("Remote Host", lh or "<none>")])
    if cmd == "system syslog config set":
        if "loghost" in o:
            s["adv"]["/Syslog/global/logHost"]["str"] = o["loghost"]
        return ""
    if cmd == "system syslog reload":
        return ""
    if cmd in ("system auditrecords local enable", "system auditrecords remote enable"):
        key = "storageEnable" if "local" in cmd else "remoteEnable"
        s["adv"][f"/Syslog/global/auditRecord/{key}"]["int"] = 1
        return ""
    if cmd == "system coredump network get":
        c = s["coredump"]
        return kv([("Enabled", b(c["enabled"])), ("Host VNic", c["vnic"]), ("Network Server IP", c["ip"]),
                   ("Network Server Port", c["port"])])
    if cmd == "network firewall get":
        f = s["firewall"]
        return kv([("Default Action", f["default_action"]), ("Enabled", b(f["enabled"])), ("Loaded", "true")])
    if cmd == "network firewall set":
        if "enabled" in o:
            s["firewall"]["enabled"] = truthy(o["enabled"])
        if "default-action" in o:
            s["firewall"]["default_action"] = "PASS" if truthy(o["default-action"]) else "DROP"
        return ""
    if cmd == "network firewall ruleset list":
        return table(["Name", "Enabled"], [[n, b(r["enabled"])] for n, r in s["firewall"]["rulesets"].items()])
    if cmd == "network firewall ruleset set":
        r = s["firewall"]["rulesets"].get(o.get("r"))
        if r is None:
            raise Fail(f"Invalid Ruleset Name: {o.get('r')}")
        if "e" in o:
            r["enabled"] = truthy(o["e"])
        if "a" in o:
            r["all"] = truthy(o["a"])
        return ""
    if cmd == "network firewall ruleset allowedip list":
        return table(["Ruleset", "Allowed IP Addresses"],
                     [[n, "All" if r["all"] else ", ".join(r["ips"])] for n, r in s["firewall"]["rulesets"].items()])
    if cmd == "system snmp get":
        n = s["snmp"]
        return kv([("Authentication", ""), ("Communities", n["communities"]), ("Enable", b(n["enable"])),
                   ("Engineid", ""), ("Hwsrc", "indications"), ("Port", 161), ("Privacy", ""), ("Syscontact", ""),
                   ("Syslocation", ""), ("Targets", ""), ("Users", "")])
    if cmd == "system snmp set":
        if "enable" in o:
            s["snmp"]["enable"] = truthy(o["enable"])
        return ""
    if cmd == "software acceptance get":
        return s["acceptance"]
    if cmd == "software acceptance set":
        order = ["VMwareCertified", "VMwareAccepted", "PartnerSupported", "CommunitySupported"]
        level = o.get("level")
        if any(order.index(v[3]) > order.index(level) for v in s["vibs"]):
            raise Fail("[AcceptanceConfigError] VIB net-usbnic's acceptance level is CommunitySupported, which is "
                       f"not compatible with the new host acceptance level {level}")
        s["acceptance"] = level
        return ""
    if cmd == "software vib list":
        return table(["Name", "Version", "Vendor", "Acceptance Level", "Install Date", "Platforms"],
                     [v + ["2024-01-15", "host"] for v in s["vibs"]])
    if cmd == "system settings encryption get":
        e = s["encryption"]
        return kv([("Mode", e["mode"]), ("Require Executables Only From Installed VIBs", b(e["exec"])),
                   ("Require Secure Boot", b(e["secure_boot"]))])
    if cmd == "system settings encryption set":
        e = s["encryption"]
        if "mode" in o:
            e["mode"] = o["mode"]
        if "require-secure-boot" in o:
            e["secure_boot"] = truthy(o["require-secure-boot"])
        if "require-exec-installed-only" in o:
            e["exec"] = truthy(o["require-exec-installed-only"])
        return ""
    for svc in ("ssh", "rhttpproxy"):
        if cmd == f"system security fips140 {svc} get":
            return kv([("Enabled", b(s["fips"][svc]))])
        if cmd == f"system security fips140 {svc} set":
            s["fips"][svc] = truthy(o.get("e"))
            return ""
    if cmd == "system account list":
        return table(["User ID", "Description"], s["accounts"])
    if cmd == "network vswitch standard list":
        out = []
        for name in s["vswitches"]:
            pgs = ", ".join(p["name"] for p in s["portgroups"] if p["vswitch"] == name)
            out += [name, kv([("Name", name), ("Class", "cswitch"), ("Num Ports", 2560), ("MTU", 1500),
                              ("Uplinks", "vmnic0"), ("Portgroups", pgs)]), ""]
        return "\n".join(out)
    if cmd in ("network vswitch standard policy security get", "network vswitch standard policy security set"):
        p = s["vswitches"].get(o.get("v"))
        if p is None:
            raise Fail(f"Unable to find vswitch {o.get('v')}")
        if cmd.endswith("set"):
            set_policy(p, o)
            return ""
        return policy_text(p)
    if cmd == "network vswitch standard portgroup list":
        return table(["Name", "Virtual Switch", "Active Clients", "VLAN ID"],
                     [[p["name"], p["vswitch"], p["clients"], p["vlan"]] for p in s["portgroups"]])
    if cmd in ("network vswitch standard portgroup policy security get",
               "network vswitch standard portgroup policy security set"):
        pg = next((p for p in s["portgroups"] if p["name"] == o.get("p")), None)
        if pg is None:
            raise Fail(f"Unable to find port group {o.get('p')}")
        if cmd.endswith("set"):
            set_policy(pg["policy"], o)
            return ""
        return policy_text(pg["policy"])
    if cmd == "iscsi adapter list":
        return table(["Adapter", "Driver", "State", "UID", "Description"],
                     [[a, "iscsi_vmk", "online", f"iscsi.{a}", "iSCSI Software Adapter"] for a in s["iscsi"]])
    if cmd == "iscsi adapter auth chap get":
        a = s["iscsi"].get(o.get("A"))
        if a is None:
            raise Fail("Invalid adapter")
        return kv([("Direction", o.get("d")), ("Level", a["mutual" if o.get("d") == "mutual" else "uni"]),
                   ("Name", ""), ("Secret", "")])
    raise Fail(f"Error: Unknown command or namespace {cmd}")


def vim_cmd(s, args):
    cmd = args[0] if args else ""
    if cmd == "hostsvc/hostsummary":
        return ("(vim.host.Summary) {\n   host = 'vim.HostSystem:ha-host',\n   config = (vim.host.Summary.ConfigSummary) "
                f"{{\n      name = \"esx01\",\n      lockdownMode = \"{s['lockdown']}\",\n   }},\n}}")
    if cmd == "vmsvc/getallvms":
        rows = [f"{vm['id']:<6} {vm['name']:<12} [{vm['ds']}] {vm['path']:<28} rhel9_64Guest   vmx-21    "
                for vm in s["vms"]]
        return "\n".join(["Vmid   Name         File                                    Guest OS        Version   "
                          "Annotation"] + rows)
    services = {"hostsvc/disable_esx_shell": ("ESXShell", 0, None), "hostsvc/stop_esx_shell": ("ESXShell", None, False),
                "hostsvc/disable_ssh": ("SSH", 0, None), "hostsvc/stop_ssh": ("SSH", None, False)}
    if cmd in services:
        name, policy, running = services[cmd]
        if policy is not None:
            s["services"][name][0] = "off"
        if running is not None:
            s["services"][name][1] = running
        return ""
    raise Fail(f"Unknown command: '{cmd}'")


def chkconfig(s, args):
    if args == ["--list"]:
        return "\n".join(f"{n:<24}{p}" for n, (p, _r) in s["services"].items())
    if len(args) == 2 and args[0] in s["services"] and args[1] in ("on", "off"):
        s["services"][args[0]][0] = args[1]
        return ""
    raise Fail("chkconfig: invalid arguments")


def initd(s, args):
    name, action = args[0], (args[1] if len(args) > 1 else "")
    if name not in s["services"]:
        raise Fail(f"sh: /etc/init.d/{name}: not found")
    label = "sfcbd" if name == "sfcbd-watchdog" else name
    if action == "status":
        if s["services"][name][1]:
            return f"{label} is running"
        print(f"{label} is not running")
        raise SystemExit(3)
    if action in ("stop", "start", "restart"):
        s["services"][name][1] = action != "stop"
        return ""
    raise Fail(f"Usage: {name} {{start|stop|status|restart}}")


def main(argv):
    path = os.environ["FAKE_ESXI_STATE"]
    with open(path) as f:
        state = json.load(f)
    tool, args = argv[0], argv[1:]
    try:
        if tool == "vmware":
            out = state["version"] + ("\n" + state["release"] if "-vl" in args else "")
        else:
            out = {"esxcli": esxcli, "vim-cmd": vim_cmd, "chkconfig": chkconfig, "initd": initd}[tool](state, args)
    except Fail as exc:
        print(str(exc))
        return 1
    with open(path, "w") as f:
        json.dump(state, f)
    if out:
        print(out)
    return 0


def install(root: str) -> dict:
    """Write the wrappers under root/bin and root/etc/init.d and the initial
    state; returns the environment to run scripts with."""
    here = os.path.dirname(os.path.abspath(__file__))
    state = initial(root)
    with open(os.path.join(root, "state.json"), "w") as f:
        json.dump(state, f)
    py = sys.executable
    wrappers = {os.path.join(root, "bin", t): t for t in ("esxcli", "vim-cmd", "chkconfig", "vmware")}
    wrappers.update({os.path.join(root, "etc/init.d", n): f"initd {n}" for n in state["services"]})
    for path, tool in wrappers.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(f"#!/bin/sh\nPYTHONPATH={here} exec {py} {os.path.abspath(__file__)} {tool} \"$@\"\n")
        os.chmod(path, 0o755)
    return {"PATH": f"{root}/bin:/usr/bin:/bin", "FAKE_ESXI_STATE": os.path.join(root, "state.json")}


def rewrite(script: str, root: str) -> str:
    """Point the host paths the module uses at the emulator's tree."""
    for p in ("/etc/init.d/", "/etc/ssh/keys-root/", "/vmfs/volumes/"):
        script = script.replace(p, root + p)
    return script


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
