"""
Redaction of secrets in device commands before they are stored or logged.

Hardening commands are built by substituting operator-supplied parameters
into templates, so the final command list can carry an enable secret, a
local-user password, an SNMP community, SNMPv3 auth/priv keys, a RADIUS/
TACACS+ key, a FortiOS ``set passwd``... The executed list is kept as
history (``HardeningAction.commands_json``) and appears in error logs; neither
needs the secret itself, and both outlive the change window.

Two independent passes, so a miss in one is caught by the other:

* value-based: every parameter whose *name* looks secret is replaced wherever
  its *value* appears - exact, and independent of device syntax;
* pattern-based: known secret-bearing CLI syntaxes (Cisco IOS, FortiOS,
  generic key=value) - covers template defaults and values typed without a
  descriptively named parameter.

Only ever apply this to copies kept for display/audit. Never to commands that
are about to be sent to a device.
"""
import re
from typing import Iterable, List, Mapping, Optional

REDACTED = "<REDACTED>"

_SECRET_NAME_RE = re.compile(
    r"pass|pwd|secret|community|key|token|psk|credential|auth_?str|priv", re.I
)
# Shorter values are too likely to collide with ordinary words/numbers
# (a key index "7", an interface "1") to be replaced blindly.
_MIN_VALUE_LEN = 4

_PATTERNS = [
    # Cisco IOS
    (re.compile(r"\b(enable\s+(?:secret|password)(?:\s+\d)?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:password|secret)(?:\s+\d)?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(snmp-server\s+community)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(snmp-server\s+user\s+.*?\bauth\s+\S+)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(priv\s+(?:des|3des|aes)(?:\s+\d+)?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b((?:tacacs|radius)-server\b.*?\bkey(?:\s+\d)?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"^(\s*key(?:\s+[07])?)\s+\S+\s*$", re.I | re.M), r"\1 " + REDACTED),
    (re.compile(r"\b(key-string(?:\s+[07])?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(ntp\s+authentication-key\s+\d+\s+\S+)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b((?:message-digest-key\s+\d+\s+md5|authentication-key)(?:\s+\d)?)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(crypto\s+isakmp\s+key)\s+\S+", re.I), r"\1 " + REDACTED),
    (re.compile(r"\b(pre-shared-key(?:\s+(?:local|remote))?(?:\s+\d)?)\s+\S+", re.I), r"\1 " + REDACTED),
    # FortiOS: set <secret-field> <value>
    (re.compile(
        r"\b(set\s+(?:passwd|password|psksecret|secret|key|passphrase|ppk-secret|"
        r"auth-pwd|priv-pwd|auth-password|priv-password|community|server-secret|"
        r"secondary-secret|tertiary-secret|sso-password|ldap-password))\s+\S+",
        re.I,
    ), r"\1 " + REDACTED),
    # Generic key=value / key: value (shell, SQL, JSON-ish)
    (re.compile(r"""\b((?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*)(['"]?)[^\s'",;)]+\2""", re.I), r"\1\2" + REDACTED + r"\2"),
    # echo 'user:pass' | chpasswd
    (re.compile(r"""(echo\s+['"]?[\w.-]+:)[^\s'"|]+(?=['"]?\s*\|\s*chpasswd)""", re.I), r"\1" + REDACTED),
]


def _secret_values(parameters: Optional[Mapping[str, object]]) -> List[str]:
    if not parameters:
        return []
    values = {
        str(value)
        for name, value in parameters.items()
        if value is not None and _SECRET_NAME_RE.search(str(name))
        and len(str(value)) >= _MIN_VALUE_LEN
    }
    # Longest first, so a secret that contains another one is fully masked.
    return sorted(values, key=len, reverse=True)


def redact_text(text: str, parameters: Optional[Mapping[str, object]] = None) -> str:
    if not text:
        return text
    for value in _secret_values(parameters):
        text = text.replace(value, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_commands(
    commands: Iterable[str], parameters: Optional[Mapping[str, object]] = None
) -> List[str]:
    return [redact_text(str(command), parameters) for command in commands]
