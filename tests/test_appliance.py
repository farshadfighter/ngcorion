"""
The virtual appliance's first-boot wizard and console (appliance/ngcorion_appliance).

Nothing here touches the machine running the tests: System gets a temporary
root and a recording command runner. The license-server connection check
runs against a real local TLS server.
"""
import datetime
import ipaddress
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "appliance"))

from ngcorion_appliance import console as menu  # noqa: E402
from ngcorion_appliance import ovf, render, wizard  # noqa: E402
from ngcorion_appliance import settings as S  # noqa: E402
from ngcorion_appliance import system as sysmod  # noqa: E402
from ngcorion_appliance.system import CommandFailed, System  # noqa: E402


# ==================== helpers ====================

class Recorder:
    """Stands in for subprocess.run: records every command, answers like a healthy machine."""

    def __init__(self):
        self.calls = []

    def __call__(self, args, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append((list(args), input))
        out = ""
        if args[:2] == ["docker", "inspect"]:
            out = "healthy\n"
        elif args[:3] == ["ip", "-4", "-j"]:
            out = '[{"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},' \
                  '{"ifname":"ens192","addr_info":[{"local":"192.168.10.20","prefixlen":24}]}]'
        elif args[0] == "openssl":
            for flag in ("-keyout", "-out"):
                Path(args[args.index(flag) + 1]).write_text("pem")
        return subprocess.CompletedProcess(args, 0, out, "")

    def commands(self):
        return [c for c, _ in self.calls]


class Scripted(wizard.Console):
    """A console that answers from a list and keeps what was printed."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.output = []

    def say(self, text=""):
        self.output.append(text)

    def _next(self, prompt):
        if not self.answers:
            raise AssertionError(f"no scripted answer for: {prompt}")
        return self.answers.pop(0)

    def ask(self, prompt, default=None):
        return self._next(prompt) or (default or "")

    def secret(self, prompt):
        return self._next(prompt)

    def confirm(self, prompt, default=True):
        a = self._next(prompt)
        return default if a == "" else a.lower().startswith("y")


@pytest.fixture
def machine(tmp_path):
    for nic in ("ens192", "docker0", "lo"):
        (tmp_path / "sys/class/net" / nic).mkdir(parents=True)
    (tmp_path / "opt/ngcorion").mkdir(parents=True)
    (tmp_path / "opt/ngcorion/VERSION").write_text("2.1.0\n")
    rec = Recorder()
    return System(root=str(tmp_path), runner=rec), rec, tmp_path


GOOD_PASSWORD = "Corion-Admin-2026!"


# ==================== validation ====================

@pytest.mark.parametrize("value,expected", [("NGCorion", "ngcorion"), ("ngc-01.corp.example.", "ngc-01.corp.example")])
def test_hostnames(value, expected):
    assert S.hostname(value) == expected


@pytest.mark.parametrize("bad", ["", "-ngc", "ngc_01", "a" * 64, "ngc..corp"])
def test_bad_hostnames(bad):
    with pytest.raises(ValueError):
        S.hostname(bad)


def test_addresses_and_gateway():
    iface = S.interface_address("192.168.10.20/255.255.255.0")
    assert iface.with_prefixlen == "192.168.10.20/24"
    assert str(S.gateway("192.168.10.1", iface)) == "192.168.10.1"
    for bad in ("192.168.10.20", "192.168.10.0/24", "192.168.10.255/24", "10.0.0.1/31", "127.0.0.5/8"):
        with pytest.raises(ValueError):
            S.interface_address(bad)
    with pytest.raises(ValueError, match="not in the network"):
        S.gateway("10.0.0.1", iface)
    with pytest.raises(ValueError, match="own address"):
        S.gateway("192.168.10.20", iface)


def test_lists():
    assert S.address_list("10.0.0.53, 10.0.0.54") == ["10.0.0.53", "10.0.0.54"]
    assert S.server_list("") == []
    assert S.server_list("ntp.corp.example 10.0.0.1") == ["ntp.corp.example", "10.0.0.1"]


def test_admin_password_follows_ngcorions_policy():
    assert S.admin_password(GOOD_PASSWORD) == GOOD_PASSWORD
    with pytest.raises(ValueError, match="12"):
        S.admin_password("Short-1!")
    # "~" is not one of the special characters NGCorion counts.
    with pytest.raises(ValueError, match="special"):
        S.admin_password("CorionAdmin2026~")

    from app.schemas.user import validate_password_strength
    validate_password_strength(GOOD_PASSWORD)     # init_db.py will accept it


# ==================== rendered files ====================

def test_networkd_static_and_dhcp():
    static = S.Network("ens192", dhcp=False, address=S.interface_address("192.168.10.20/24"),
                       gateway=ipaddress.IPv4Address("192.168.10.1"), dns=["10.0.0.53", "10.0.0.54"])
    text = render.networkd(static)
    assert "Name=ens192" in text and "Address=192.168.10.20/24" in text and "Gateway=192.168.10.1" in text
    assert text.count("DNS=") == 2 and "DHCP=" not in text
    dhcp = render.networkd(S.Network("ens192"))
    assert "DHCP=ipv4" in dhcp and "Address=" not in dhcp


def test_env_file_round_trip_and_fresh_secrets():
    a, b = render.new_secrets(), render.new_secrets()
    assert a != b and len(a["SECRET_KEY"]) == 64
    env = render.parse_env(render.env_file(a))
    assert env["SECRET_KEY"] == a["SECRET_KEY"] and env["POSTGRES_PASSWORD"] == a["POSTGRES_PASSWORD"]
    # The license server is built into NGCorion: nothing about it in the installation's settings.
    assert not any(k.startswith("LICENSE") for k in env)


# ==================== OVF properties ====================

OVF_ENV = """<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1"
             xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" oe:id="">
  <PlatformSection><Kind>VMware ESXi</Kind></PlatformSection>
  <PropertySection>
    <Property oe:key="ngcorion.hostname" oe:value="ngc01"/>
    <Property oe:key="ngcorion.ip" oe:value="{ip}"/>
    <Property oe:key="ngcorion.gateway" oe:value="192.168.10.1"/>
    <Property oe:key="ngcorion.dns" oe:value="10.0.0.53"/>
    <Property oe:key="ngcorion.ntp" oe:value=""/>
    <Property oe:key="ngcorion.admin_password" oe:value="{pw}"/>
    <Property oe:key="other.key" oe:value="ignored"/>
  </PropertySection>
</Environment>"""


def test_ovf_static_configuration():
    props = ovf.parse(OVF_ENV.format(ip="192.168.10.20/24", pw=GOOD_PASSWORD))
    assert "other.key" not in props and "ngcorion.ntp" not in props
    assert ovf.complete(props)
    st, pw = ovf.to_settings(props, "ens192")
    assert (st.hostname, st.network.dhcp, str(st.network.address), pw) == ("ngc01", False, "192.168.10.20/24", GOOD_PASSWORD)


def test_ovf_dhcp_and_errors_name_the_property():
    st, _ = ovf.to_settings(ovf.parse(OVF_ENV.format(ip="", pw=GOOD_PASSWORD)), "ens192")
    assert st.network.dhcp
    with pytest.raises(ValueError, match="ngcorion.admin_password"):
        ovf.to_settings(ovf.parse(OVF_ENV.format(ip="", pw="weak")), "ens192")
    assert not ovf.complete({"ngcorion.hostname": "x"})


# ==================== applying ====================

def test_secrets_are_made_once(machine):
    system, _, root = machine
    first = system.ensure_env()
    second = system.ensure_env()
    assert first == second                      # the database was initialised with this password
    env_path = root / "opt/ngcorion/.env"
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"


def test_admin_password_never_on_a_command_line(machine):
    system, rec, _ = machine
    system.create_admin(GOOD_PASSWORD)
    system.reset_admin_password(GOOD_PASSWORD)
    for args, stdin in rec.calls:
        assert GOOD_PASSWORD not in " ".join(args)
        assert stdin == GOOD_PASSWORD + "\n"


def test_interfaces_skip_docker_and_loopback(machine):
    system, _, _ = machine
    assert system.interfaces() == ["ens192"]
    assert system.web_urls() == ["https://192.168.10.20/"]


def test_wizard_end_to_end(machine, monkeypatch):
    system, rec, root = machine
    monkeypatch.setattr(wizard, "check_license_server", lambda: (True, "lic.ngcorion.com is reachable"))
    con = Scripted([
        "ngc01",                        # host name
        "2",                            # static
        "192.168.10.20/24", "", "",     # address, gateway (default .1), DNS (default gateway)
        "",                             # NTP
        "weak", GOOD_PASSWORD, GOOD_PASSWORD,
        "y",                            # apply
    ])
    assert wizard.run(con, system)
    assert any("At least 12" in line for line in con.output)
    assert not any("License server address" in line for line in con.output)   # never asked
    assert any("lic.ngcorion.com is reachable" in line for line in con.output)

    net = (root / "etc/systemd/network/10-ngcorion.network").read_text()
    assert "Address=192.168.10.20/24" in net and "Gateway=192.168.10.1" in net and "DNS=192.168.10.1" in net
    assert (root / "etc/hostname").read_text() == "ngc01\n"
    env = render.parse_env((root / "opt/ngcorion/.env").read_text())
    assert env["SECRET_KEY"] and not any(k.startswith("LICENSE") for k in env)
    assert (root / "opt/ngcorion/traefik/certs/ngcorion.local.key").exists()
    assert system.configured()

    order = [c[:3] for c in rec.commands()]
    assert order.index(["networkctl", "reload"]) < order.index(["systemctl", "start", "ngcorion.service"])
    assert any("init_db.py" in " ".join(c) for c in rec.commands())


def test_wizard_can_start_over_before_changing_anything(machine, monkeypatch):
    system, rec, root = machine
    monkeypatch.setattr(wizard, "check_license_server", lambda: (True, "lic.ngcorion.com is reachable"))
    con = Scripted(["a", "1", "", GOOD_PASSWORD, GOOD_PASSWORD, "n",
                    "b", "1", "", GOOD_PASSWORD, GOOD_PASSWORD, "y"])
    assert wizard.run(con, system)
    assert (root / "etc/hostname").read_text() == "b\n"


def test_failed_start_is_reported_and_not_marked_configured(machine, monkeypatch):
    system, _, _ = machine
    monkeypatch.setattr(wizard, "check_license_server", lambda: (True, "lic.ngcorion.com is reachable"))
    monkeypatch.setattr(System, "wait_healthy", lambda self, **kw: False)
    con = Scripted(["ngc", "1", "", GOOD_PASSWORD, GOOD_PASSWORD, "y"])
    assert not wizard.run(con, system)
    assert any("Setup stopped" in line for line in con.output)
    assert not system.configured()


# ==================== license server connection check (real TLS) ====================

@pytest.fixture
def tls_server(tmp_path):
    """A local HTTPS endpoint with a self-signed certificate for 127.0.0.1."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "license-server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    (tmp_path / "c.pem").write_text(pem)
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    (tmp_path / "ca.pem").write_text(pem)
    yield sock.getsockname()[1], str(tmp_path / "ca.pem")
    stop.set()
    t.join()
    sock.close()


def test_unreachable_license_server_is_explained(machine, monkeypatch):
    ok, detail = sysmod.check_license_server("no-such-host.invalid")
    assert not ok and "DNS" in detail
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    ok, detail = sysmod.check_license_server("127.0.0.1", port)
    assert not ok and "firewall" in detail


def test_a_foreign_certificate_is_reported_but_the_server_is_reachable(tls_server):
    # NGCorion checks the signed answers, not this certificate (app/core/license_client.py): a
    # certificate that is not the public one is a warning about the path, not a failure.
    port, ca = tls_server
    ok, detail = sysmod.check_license_server("127.0.0.1", port)       # self-signed: not public
    assert ok and "intercepting" in detail and "signature" in detail
    assert sysmod.check_license_server("127.0.0.1", port, cafile=ca) == (True, "127.0.0.1 is reachable")


def test_an_incomplete_chain_is_named_as_such(tls_server, tmp_path):
    # As lic.ngcorion.com: the server sends its certificate without the one that links it to a
    # root - here a leaf from a test CA, sent alone; with the CA it verifies.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lic")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.key").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "root.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    port = _serve_tls(tmp_path / "leaf.pem", tmp_path / "leaf.key")

    ok, detail = sysmod.check_license_server("127.0.0.1", port)
    assert ok and "chain is incomplete" in detail
    assert sysmod.check_license_server("127.0.0.1", port, cafile=str(tmp_path / "root.pem")) == \
        (True, "127.0.0.1 is reachable")


def _serve_tls(cert, key):
    """Answer TLS handshakes on a local port in the background, for the rest of the test run."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_no_tls_at_all_is_a_failure():
    plain = socket.socket()
    plain.bind(("127.0.0.1", 0))
    plain.listen(1)

    def answer():
        conn, _ = plain.accept()
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    ok, detail = sysmod.check_license_server("127.0.0.1", plain.getsockname()[1], timeout=5)
    plain.close()
    assert not ok and "no TLS connection" in detail


def test_setup_goes_on_when_the_license_server_is_unreachable(machine, monkeypatch):
    system, _, _ = machine
    monkeypatch.setattr(wizard, "check_license_server",
                        lambda: (False, "lic.ngcorion.com cannot be resolved (x); check the DNS servers"))
    con = Scripted(["ngc", "1", "", GOOD_PASSWORD, GOOD_PASSWORD, "y"])
    assert wizard.run(con, system)
    assert any("not reachable" in line and "DNS" in line for line in con.output)
    assert system.configured()


# ==================== console menu ====================

def test_menu_offers_setup_only_until_configured(machine):
    system, _, _ = machine
    assert "First-start setup" in [label for label, _ in menu.menu_items(system)]
    system.mark_configured()
    labels = [label for label, _ in menu.menu_items(system)]
    assert "First-start setup" not in labels and "Shut down" in labels


def test_menu_reset_password_and_errors_stay_in_the_menu(machine, monkeypatch):
    system, rec, _ = machine
    system.mark_configured()
    labels = [label for label, _ in menu.menu_items(system)]
    idx = str(labels.index("Reset the web administrator's password") + 1)
    menu.run_once(Scripted([idx, GOOD_PASSWORD, GOOD_PASSWORD]), system)
    assert any(stdin == GOOD_PASSWORD + "\n" and "python" in args for args, stdin in rec.calls)

    def broken(self, name):
        raise CommandFailed("hostname: permission denied")
    monkeypatch.setattr(System, "apply_hostname", broken)
    con = Scripted([str(labels.index("Host name") + 1), "ngc02"])
    menu.run_once(con, system)                   # no exception escapes to a shell
    assert any("permission denied" in line for line in con.output)


def test_a_failed_start_reports_the_compose_error(machine):
    system, rec, _ = machine

    def runner(args, input=None, capture_output=True, text=True, timeout=None):
        if args[:2] == ["systemctl", "start"]:
            return subprocess.CompletedProcess(args, 1, "", "Job for ngcorion.service failed because the control process exited with error code.")
        return rec(args, input=input)
    system.runner = runner
    with pytest.raises(CommandFailed, match="Job for ngcorion.service failed"):
        system.start_stack()


def test_log_shows_why_the_stack_did_not_start(machine):
    system, rec, _ = machine

    def runner(args, input=None, capture_output=True, text=True, timeout=None):
        if args[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(args, 0, "backend\tCreated\npostgres\tUp 2 minutes (healthy)\n", "")
        if args[0] == "journalctl":
            return subprocess.CompletedProcess(args, 0, "dependency failed to start: container postgres is unhealthy\n", "")
        return rec(args, input=input)
    system.runner = runner
    assert "container postgres is unhealthy" in system.logs()


# ==================== the disk ====================

def _disk_machine(machine, fstype="ext4", growpart=(0, "CHANGED: partition=1 start=2048 old: size=1 new: size=2", "")):
    """The machine of `machine`, with / on /dev/sda1 and growpart answering `growpart`."""
    system, rec, root = machine
    (root / "sys/class/block/sda1").mkdir(parents=True)
    (root / "sys/class/block/sda1/partition").write_text("1\n")
    (root / "sys/class/block/sda/device").mkdir(parents=True)
    (root / "sys/class/block/sda/device/rescan").write_text("")

    def runner(args, input=None, capture_output=True, text=True, timeout=None):
        rec.calls.append((list(args), input))
        if args[0] == "findmnt":
            return subprocess.CompletedProcess(args, 0, f"/dev/sda1 {fstype}\n", "")
        if args[0] == "lsblk":
            return subprocess.CompletedProcess(args, 0, "sda\n", "")
        if args[0] == "growpart":
            return subprocess.CompletedProcess(args, *growpart)
        return subprocess.CompletedProcess(args, 0, "", "")
    system.runner = runner
    return system, rec, root


def test_the_disk_grows_into_an_enlarged_virtual_disk(machine):
    system, rec, root = _disk_machine(machine)
    assert system.grow_disk().startswith("The disk was grown")
    assert ["growpart", "/dev/sda", "1"] in rec.commands()
    assert ["resize2fs", "/dev/sda1"] in rec.commands()
    assert (root / "sys/class/block/sda/device/rescan").read_text() == "1"     # new size read first


def test_nothing_to_grow_changes_nothing(machine):
    system, rec, _ = _disk_machine(machine, growpart=(1, "NOCHANGE: partition 1 is size 125827039. it cannot be grown\n", ""))
    assert system.grow_disk() == "The disk is already used to its full size."
    assert not [c for c in rec.commands() if c[0] in ("resize2fs", "xfs_growfs")]


def test_an_xfs_root_is_grown_with_xfs_growfs(machine):
    system, rec, _ = _disk_machine(machine, fstype="xfs")
    system.grow_disk()
    assert ["xfs_growfs", "/"] in rec.commands()


def test_a_growpart_failure_is_reported(machine):
    system, _, _ = _disk_machine(machine, growpart=(2, "", "FAILED: sfdisk failed\n"))
    with pytest.raises(CommandFailed, match="sfdisk failed"):
        system.grow_disk()


def test_a_root_that_is_not_a_partition_is_left_alone(machine):
    system, rec, _ = machine

    def runner(args, input=None, capture_output=True, text=True, timeout=None):
        rec.calls.append((list(args), input))
        out = "/dev/mapper/vg-root ext4\n" if args[0] == "findmnt" else ""
        return subprocess.CompletedProcess(args, 0, out, "")
    system.runner = runner
    assert "could not be identified" in system.grow_disk()
    assert not [c for c in rec.commands() if c[0] == "growpart"]


def test_the_console_shows_the_disk_and_can_grow_it(machine):
    system, rec, _ = _disk_machine(machine)
    system.mark_configured()
    con = Scripted([])
    menu._status(con, system)
    assert any(line.startswith(" Disk: ") and "GiB used of" in line for line in con.output)
    labels = [label for label, _ in menu.menu_items(system)]
    con = Scripted([str(labels.index("Use the whole disk (after enlarging it)") + 1)])
    menu.run_once(con, system)
    assert ["resize2fs", "/dev/sda1"] in rec.commands()


def test_growdisk_runs_at_every_start():
    unit = (ROOT / "appliance/rootfs/etc/systemd/system/ngcorion-growdisk.service").read_text()
    assert "ExecStart=/usr/bin/python3 -m ngcorion_appliance growdisk" in unit
    assert "ngcorion-growdisk.service" in (ROOT / "appliance/provision/20-ngcorion.sh").read_text()
    base = (ROOT / "appliance/provision/10-base.sh").read_text()
    assert "cloud-guest-utils" in base                                   # growpart
    assert "cloud-guest-utils" not in (ROOT / "appliance/provision/30-harden.sh").read_text().split(
        "apt-get purge", 1)[1].splitlines()[0]
