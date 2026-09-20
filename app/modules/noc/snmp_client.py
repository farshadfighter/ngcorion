"""
SNMP polling client for NOC monitoring.

Thin wrapper around `puresnmp` (pure-Python, no net-snmp C bindings needed -
fits the slim Docker image the same way the rest of this app's dependencies
do): one device-level poll (MIB-2 system group) and one interface-level walk
(IF-MIB ifTable), both read-only GETs/WALKs - this module never writes
anything to a device.
"""
import asyncio
from dataclasses import dataclass, field

from puresnmp import Client, PyWrapper, V2C, V3, Auth, Priv
from puresnmp.exc import Timeout, SnmpError

from app.models.noc import AssetSnmpCredential
from app.core.snmp_crypto import decrypt_secret

# MIB-2 "system" group (RFC 1213)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# IF-MIB ifTable columns (RFC 2863) - base OID + column number, walked
# together and joined by their shared trailing if_index.
IF_TABLE_BASE = "1.3.6.1.2.1.2.2.1"
IF_COLUMNS = {
    "if_descr": f"{IF_TABLE_BASE}.2",
    "if_type": f"{IF_TABLE_BASE}.3",
    "if_speed": f"{IF_TABLE_BASE}.5",
    "if_admin_status": f"{IF_TABLE_BASE}.7",
    "if_oper_status": f"{IF_TABLE_BASE}.8",
    "in_octets": f"{IF_TABLE_BASE}.10",
    "out_octets": f"{IF_TABLE_BASE}.16",
}
IF_STATUS_NAMES = {1: "up", 2: "down", 3: "testing"}

DEFAULT_TIMEOUT_SECONDS = 3.0


@dataclass
class InterfacePollResult:
    if_index: int
    if_descr: str | None = None
    if_type: int | None = None
    if_speed: int | None = None
    if_admin_status: str | None = None
    if_oper_status: str | None = None
    in_octets: int | None = None
    out_octets: int | None = None


@dataclass
class DevicePollResult:
    reachable: bool
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_contact: str | None = None
    sys_location: str | None = None
    sys_uptime_ticks: int | None = None
    error_message: str | None = None
    interfaces: list[InterfacePollResult] = field(default_factory=list)


def _build_credentials(credential: AssetSnmpCredential):
    if credential.version == "v3":
        auth = None
        if credential.auth_key_encrypted:
            auth = Auth(
                key=decrypt_secret(credential.auth_key_encrypted).encode(),
                method=(credential.auth_protocol or "SHA").lower(),
            )
        priv = None
        if credential.priv_key_encrypted:
            priv = Priv(
                key=decrypt_secret(credential.priv_key_encrypted).encode(),
                method=(credential.priv_protocol or "AES").lower(),
            )
        return V3(credential.username or "", auth, priv)

    community = decrypt_secret(credential.community_encrypted) if credential.community_encrypted else "public"
    return V2C(community)


def _decode(value) -> str | int | None:
    """puresnmp returns bytes for OCTET STRING values; decode defensively -
    device-supplied strings are not guaranteed valid UTF-8."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


async def poll_asset(
    host: str, credential: AssetSnmpCredential, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> DevicePollResult:
    """One full poll of a device: system group + interface table.

    Never raises - an unreachable device or a bad credential comes back as
    `reachable=False` with `error_message` set, exactly like every other
    device-I/O path in this app reports a connectivity failure without
    crashing the caller.
    """
    client = PyWrapper(Client(host, _build_credentials(credential), port=credential.port))

    try:
        sys_descr, sys_uptime, sys_contact, sys_name, sys_location = await asyncio.wait_for(
            client.multiget([OID_SYS_DESCR, OID_SYS_UPTIME, OID_SYS_CONTACT, OID_SYS_NAME, OID_SYS_LOCATION]),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return DevicePollResult(reachable=False, error_message=f"SNMP request to {host}:{credential.port} timed out")
    except Timeout:
        return DevicePollResult(reachable=False, error_message=f"SNMP request to {host}:{credential.port} timed out")
    except SnmpError as exc:
        return DevicePollResult(reachable=False, error_message=str(exc))
    except Exception as exc:  # noqa: BLE001 - any transport/credential error means "unreachable", not a crash
        return DevicePollResult(reachable=False, error_message=f"{type(exc).__name__}: {exc}")

    result = DevicePollResult(
        reachable=True,
        sys_descr=_decode(sys_descr),
        sys_uptime_ticks=int(sys_uptime) if sys_uptime is not None else None,
        sys_contact=_decode(sys_contact),
        sys_name=_decode(sys_name),
        sys_location=_decode(sys_location),
    )

    # Interface table: best-effort. A device that answers the system group
    # but not IF-MIB (rare, but seen on some appliances) still counts as
    # reachable - it just has no interfaces listed.
    try:
        varbinds = await asyncio.wait_for(_collect_walk(client, list(IF_COLUMNS.values())), timeout=timeout)
        by_index: dict[int, dict] = {}
        for varbind in varbinds:
            oid_str = str(varbind.oid)
            column = next(name for name, oid in IF_COLUMNS.items() if oid_str.startswith(oid + "."))
            if_index = int(oid_str.rsplit(".", 1)[-1])
            by_index.setdefault(if_index, {})[column] = varbind.value

        for if_index, fields in sorted(by_index.items()):
            result.interfaces.append(
                InterfacePollResult(
                    if_index=if_index,
                    if_descr=_decode(fields.get("if_descr")),
                    if_type=fields.get("if_type"),
                    if_speed=fields.get("if_speed"),
                    if_admin_status=IF_STATUS_NAMES.get(fields.get("if_admin_status")),
                    if_oper_status=IF_STATUS_NAMES.get(fields.get("if_oper_status")),
                    in_octets=fields.get("in_octets"),
                    out_octets=fields.get("out_octets"),
                )
            )
    except (asyncio.TimeoutError, Timeout, SnmpError, Exception):  # noqa: BLE001
        # Interfaces are a bonus, not required for "reachable" - swallow and
        # report the device-level data we already have.
        pass

    return result


async def _collect_walk(client, oids: list[str]) -> list:
    return [varbind async for varbind in client.multiwalk(oids)]
