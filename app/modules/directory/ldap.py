"""
Talking to Active Directory or another LDAP directory (ldap3): connect over TLS, find a user, check
a password, list the user's groups. No database, no settings storage: callers pass a Settings.

Only encrypted connections exist: LDAPS (636) or StartTLS (389), the server certificate checked
against the CA the administrator uploaded (or the system's CAs) and its name against the server
address. Every value put in a search filter is escaped (RFC 4515), and an empty password is
refused before any bind: LDAP treats a bind with a name and no password as an anonymous bind that
"succeeds".
"""
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPStartTLSError
from ldap3.utils.conv import escape_filter_chars

CONNECT_TIMEOUT = 5
RECEIVE_TIMEOUT = 10
# Active Directory: groups the user belongs to directly or through other groups, in one query.
AD_IN_CHAIN = "1.2.840.113556.1.4.1941"
AD_DISABLED = 0x2                       # userAccountControl ACCOUNTDISABLE
NESTING_DEPTH = 8                       # other directories: groups of groups, followed this deep

DEFAULTS = {
    "ad": {"user_attr": "sAMAccountName", "user_filter": "(&(objectCategory=person)(objectClass=user))",
           "group_filter": "(objectClass=group)"},
    "ldap": {"user_attr": "uid", "user_filter": "(objectClass=inetOrgPerson)",
             "group_filter": "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"},
}
USER_ATTRS = ["mail", "displayName", "cn", "userAccountControl", "memberOf"]


class DirectoryUnavailable(Exception):
    """No directory server could be reached or the service account was refused. The message is
    for the administrator (System Configuration); sign-in shows a general one."""


@dataclass
class Settings:
    kind: str                         # "ad" | "ldap"
    servers: List[str]                # host or host:port, tried in order
    security: str                     # "ldaps" | "starttls"
    base_dn: str
    bind_dn: str
    bind_password: str
    ca_pem: str = ""
    user_attr: str = ""
    user_filter: str = ""
    group_filter: str = ""

    def attr(self) -> str:
        return self.user_attr or DEFAULTS[self.kind]["user_attr"]

    def ufilter(self) -> str:
        return self.user_filter or DEFAULTS[self.kind]["user_filter"]

    def gfilter(self) -> str:
        return self.group_filter or DEFAULTS[self.kind]["group_filter"]


@dataclass
class DirectoryUser:
    dn: str
    username: str                     # the directory's own spelling of the name
    email: Optional[str]
    display_name: Optional[str]
    disabled: bool
    groups: Set[str] = field(default_factory=set)   # DNs


def norm_dn(dn: str) -> str:
    return ",".join(part.strip() for part in (dn or "").split(",")).lower()


def _tls(s: Settings) -> Tls:
    kwargs = {"validate": ssl.CERT_REQUIRED}     # the default context: TLS 1.2+, strict X.509 checks
    if s.ca_pem.strip():
        kwargs["ca_certs_data"] = s.ca_pem          # otherwise the system's trusted CAs
    return Tls(**kwargs)


def _server(s: Settings, address: str) -> Server:
    host, _, port = address.strip().partition(":")
    ldaps = s.security == "ldaps"
    return Server(host, port=int(port) if port else (636 if ldaps else 389), use_ssl=ldaps, tls=_tls(s),
                  get_info=NONE, connect_timeout=CONNECT_TIMEOUT)


def _open(s: Settings, address: str, user: str, password: str) -> Connection:
    """A connection bound as `user`; raises LDAPBindError for a refused password and other
    LDAPException for transport problems."""
    if not password:
        raise LDAPBindError("empty password")
    conn = Connection(_server(s, address), user=user, password=password, receive_timeout=RECEIVE_TIMEOUT,
                      raise_exceptions=False, read_only=True)
    try:
        conn.open()
        if s.security == "starttls" and not conn.start_tls():
            raise LDAPStartTLSError("StartTLS was refused")
        if not conn.bind():
            raise LDAPBindError(conn.result.get("description") or "invalid credentials")
    except Exception:
        conn.unbind()
        raise
    return conn


def _reason(exc: Exception) -> str:
    text = str(exc)
    if "doesn't match any name" in text:
        return "the server's certificate does not carry the name used to reach it"
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return "the server's certificate is not trusted (upload the CA certificate) or does not match its name"
    if "timed out" in text or "timeout" in text.lower():
        return "no answer in time"
    if "refused" in text.lower() and "StartTLS" not in text:
        return "connection refused"
    return text[:200] or exc.__class__.__name__


class Session:
    """The service account's connection, opened on the first server that answers."""

    def __init__(self, s: Settings):
        self.s = s
        problems = []
        for address in s.servers:
            try:
                self.conn = _open(s, address, s.bind_dn, s.bind_password)
                self.address = address
                return
            except LDAPBindError:
                raise DirectoryUnavailable(f"{address}: the service account was refused (check its name and password)")
            except (LDAPException, OSError) as exc:
                problems.append(f"{address}: {_reason(exc)}")
        raise DirectoryUnavailable("; ".join(problems) or "no directory server is configured")

    def close(self) -> None:
        self.conn.unbind()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _search(self, base: str, flt: str, attrs, scope=SUBTREE, size: int = 0):
        ok = self.conn.search(base, flt, search_scope=scope, attributes=attrs, size_limit=size)
        if not ok and self.conn.result.get("result") not in (0, 4, 32):   # success, size limit, no such object
            raise DirectoryUnavailable(f"{self.address}: search failed ({self.conn.result.get('description')})")
        return [e for e in self.conn.response or [] if e.get("type") == "searchResEntry"]

    def find_user(self, username: str) -> Optional[DirectoryUser]:
        name = (username or "").strip()
        if not name or len(name) > 256:
            return None
        flt = f"(&{self.s.ufilter()}({self.s.attr()}={escape_filter_chars(name)}))"
        found = self._search(self.s.base_dn, flt, USER_ATTRS + [self.s.attr()], size=2)
        if len(found) != 1:          # nobody, or the name is not unique: never guess
            return None
        entry = found[0]
        attrs = entry.get("attributes") or {}

        def one(key):
            value = attrs.get(key)
            if isinstance(value, list):
                value = value[0] if value else None
            return str(value) if value not in (None, "") else None

        uac = attrs.get("userAccountControl")
        uac = uac[0] if isinstance(uac, list) and uac else uac
        disabled = self.s.kind == "ad" and bool(int(uac or 0) & AD_DISABLED)
        return DirectoryUser(dn=entry["dn"], username=one(self.s.attr()) or name, email=one("mail"),
                             display_name=one("displayName") or one("cn"), disabled=disabled)

    def groups_of(self, user: DirectoryUser) -> Set[str]:
        """Every group the user is in, directly or through other groups (DNs as the directory spells
        them; compare with norm_dn)."""
        if self.s.kind == "ad":
            flt = f"(&{self.s.gfilter()}(member:{AD_IN_CHAIN}:={escape_filter_chars(user.dn)}))"
            return {e["dn"] for e in self._search(self.s.base_dn, flt, ["cn"])}
        seen: Dict[str, str] = {}
        frontier = [user.dn]
        for _ in range(NESTING_DEPTH):
            nxt = []
            for dn in frontier:
                v = escape_filter_chars(dn)
                flt = f"(&{self.s.gfilter()}(|(member={v})(uniqueMember={v})))"
                for e in self._search(self.s.base_dn, flt, ["cn"]):
                    key = norm_dn(e["dn"])
                    if key not in seen:
                        seen[key] = e["dn"]
                        nxt.append(e["dn"])
            if not nxt:
                break
            frontier = nxt
        return set(seen.values())

    def check_password(self, user: DirectoryUser, password: str) -> bool:
        """The user's own password, by binding as them on the server that answered."""
        try:
            conn = _open(self.s, self.address, user.dn, password)
        except LDAPBindError:
            return False
        except (LDAPException, OSError) as exc:
            raise DirectoryUnavailable(f"{self.address}: {_reason(exc)}")
        conn.unbind()
        return True

    def search_groups(self, text: str, limit: int = 25) -> List[Dict[str, str]]:
        """Groups whose name contains `text`, for the mapping editor."""
        flt = f"(&{self.s.gfilter()}(cn=*{escape_filter_chars(text.strip())}*))" if text.strip() else self.s.gfilter()
        out = []
        for e in self._search(self.s.base_dn, flt, ["cn"], size=limit):
            cn = (e.get("attributes") or {}).get("cn")
            cn = cn[0] if isinstance(cn, list) and cn else cn
            out.append({"dn": e["dn"], "name": str(cn or e["dn"])})
        return sorted(out, key=lambda g: g["name"].lower())

    def exists(self, dn: str) -> bool:
        return bool(self._search(dn, "(objectClass=*)", ["cn"], scope=BASE))
