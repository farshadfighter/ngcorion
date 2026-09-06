"""
Shared parameter-substitution security for hardening command templates.

Every hardening module (linux, windows, mssql, mongodb, apache, cisco,
fortinet) accepts a free-form ``Dict[str, str]`` of operator-supplied values
from the API and substitutes them into ``{PARAM}``/``<PARAM>`` placeholders
inside command/script/SQL templates that are then executed on a managed
device, host, or database. Naive ``str.replace()`` substitution (still used
by several modules) lets a malicious or malformed value break out of the
surrounding shell command, PowerShell script, SQL statement, or device CLI
line and inject arbitrary commands.

This module centralizes the validation/escaping primitives every module
needs, so the security-critical logic exists in one tested place instead of
seven independent (and inconsistently correct) reimplementations. Each
module still owns *which* primitive applies to *which* parameter — that
mapping is inherently template-specific — but the primitives themselves,
and the exception type routers already know how to turn into a clean HTTP
400, live here.

Primitive families:

  CLI_LINE            Single-line value sent to an interactive, line-oriented
                       device CLI (Cisco IOS, FortiOS) that has no shell/SQL
                       metacharacter semantics of its own. The only real
                       injection primitive there is an embedded newline/CR,
                       which the device reads as an Enter keypress and a
                       fresh command line. See ``validate_cli_line``.

  DELIMITED_MULTILINE Free multi-line text inserted between two literal
                       delimiter markers (a Cisco/FortiOS ``banner ^text^``,
                       or a POSIX heredoc). Newlines are the point; the risk
                       is the delimiter reappearing inside the value and
                       closing the block early, exposing whatever follows to
                       be parsed as fresh shell/device input. See
                       ``validate_heredoc_body`` (line-exact POSIX heredoc
                       matching) and ``validate_delimited_text`` (substring
                       matching, for non-line-oriented delimiters like a
                       single ``^`` character).

  SHELL_BREAKOUT_DENY Free text embedded somewhere inside a POSIX shell
                       command line that will run via ``sh -c``, in a
                       position that may be a bare unquoted word, or may
                       already sit inside an existing single-quoted region
                       (a sed program, an echo/printf argument). A single
                       denylist of the handful of characters that are
                       dangerous in *either* context keeps ordinary path/
                       host/config-value punctuation (``. / : - | ! ~ @``,
                       spaces) usable while closing every break-out. See
                       ``reject_shell_breakout_chars``.

  RESTRICTED CHARSETS  Stricter allowlists for values with a well-defined
                       shape (a filesystem path, a bare identifier, a host/
                       IP list) where an allowlist is both safer and simpler
                       than trying to reason about every embedding context.
                       See ``validate_path``, ``validate_identifier``,
                       ``validate_host_list``.

  POWERSHELL_SINGLE_Q Value inserted inside an existing PowerShell
                       single-quoted string literal (``'...'``). PowerShell
                       single-quoted strings do not interpret ``$`` or
                       backticks, so escaping just needs to double any
                       embedded ``'``. See ``escape_powershell_single_quoted``.

  SQL_IDENTIFIER       Value inserted inside a T-SQL ``[bracket]``-quoted
                       identifier or a ``'string'``-quoted literal (some
                       templates use the same placeholder in both contexts
                       across statements/verify_statements). Denying the
                       characters that can close *either* delimiter is safe
                       in both. See ``escape_sql_identifier_text``.

  INTEGER / SELECT     Numeric and enum-constrained values. See
                       ``validate_integer`` and ``validate_select``.
"""

from __future__ import annotations

import re
import shlex
from typing import Iterable, Optional, Sequence


class ParameterSecurityError(ValueError):
    """
    A hardening parameter value failed security validation before being
    substituted into a template that will execute on a managed target.

    Subclasses ValueError deliberately: every hardening router already
    converts a ValueError raised while building/running a fix into a clean
    HTTP 400 (``except ValueError as e: raise HTTPException(400, str(e))``),
    so raising this from deep inside template substitution surfaces as a
    normal validation error with no router changes required.
    """


def _fail(field: str, reason: str) -> None:
    raise ParameterSecurityError(f"Parameter {field}: {reason}")


# C0 control characters (0x00-0x1F) plus DEL (0x7F). NUL is included and
# called out on its own everywhere below since it is dangerous even to
# libraries that otherwise treat strings as opaque bytes.
_CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {chr(0x7F)}
_NEWLINE_CHARS = frozenset({"\n", "\r"})


def _check_length(value: str, field: str, max_length: int) -> None:
    if len(value) > max_length:
        _fail(field, f"is too long ({len(value)} chars, max {max_length})")


def _reject_control_chars(value: str, field: str, *, allow_newlines: bool) -> None:
    forbidden = _CONTROL_CHARS - (_NEWLINE_CHARS if allow_newlines else frozenset())
    for ch in value:
        if ch in forbidden:
            _fail(field, f"contains a control character (0x{ord(ch):02x}), which is not allowed")


# --------------------------------------------------------------------------- #
#  CLI_LINE — device CLI (Cisco IOS / FortiOS) single-line values
# --------------------------------------------------------------------------- #

def validate_cli_line(value: object, field: str, *, max_length: int = 1024) -> str:
    """
    Validate a value substituted into a single line sent to a line-oriented
    device CLI (Cisco IOS, FortiOS) over an interactive SSH session.

    These CLIs have no shell/SQL metacharacter semantics: punctuation like
    ``$ ` ; | &`` is inert in a password, hostname, or ACL name. The one
    real injection primitive is an embedded newline/carriage-return, which
    the device reads as pressing Enter mid-command and starting a fresh
    line — letting a malicious value append an arbitrary extra CLI command
    (e.g. a second, attacker-chosen config line) after the intended one.
    """
    value = str(value)
    _check_length(value, field, max_length)
    _reject_control_chars(value, field, allow_newlines=False)
    return value


# --------------------------------------------------------------------------- #
#  DELIMITED_MULTILINE — banners / heredoc bodies
# --------------------------------------------------------------------------- #

def validate_heredoc_body(value: object, field: str, *, delimiter: str = "EOF",
                           max_length: int = 8192) -> str:
    """
    Validate free multi-line text destined for a POSIX heredoc body
    (``cat > file << 'DELIM' ... DELIM``). Newlines are the entire point of
    a textarea banner/MOTD field, so they are allowed — but a heredoc ends
    at the first *line* that, once stripped of surrounding whitespace,
    equals the delimiter word exactly. A value that happens to contain such
    a line closes the heredoc early; everything the caller appends after it
    (including the template's own trailing text) is then parsed as fresh
    shell input by the ``sh -c`` that runs the whole command — arbitrary
    command execution with the same privileges as the fix itself.
    """
    value = str(value)
    _check_length(value, field, max_length)
    if "\x00" in value:
        _fail(field, "contains a NUL byte")
    for line in value.splitlines():
        if line.strip() == delimiter:
            _fail(
                field,
                f"contains a line equal to {delimiter!r}, which would terminate "
                "the surrounding heredoc early",
            )
    return value


def validate_delimited_text(value: object, field: str, *, delimiter: str,
                             max_length: int = 8192) -> str:
    """
    Validate free multi-line text inserted between two literal occurrences
    of a single delimiter *character* (not line-anchored) — e.g. a Cisco/
    FortiOS ``banner motd ^text^`` where the device reads characters until
    the delimiter reappears, wherever it falls, not just at line starts.
    Newlines are allowed (multi-line banners are the whole point); an
    embedded copy of the delimiter itself is not, since it closes the
    banner definition early and lets to whatever follows be parsed as a
    fresh CLI command.
    """
    value = str(value)
    _check_length(value, field, max_length)
    if "\x00" in value:
        _fail(field, "contains a NUL byte")
    if delimiter and delimiter in value:
        _fail(
            field,
            f"must not contain the literal delimiter {delimiter!r} used to "
            "close this block",
        )
    return value


# --------------------------------------------------------------------------- #
#  SHELL_BREAKOUT_DENY — free text embedded in a POSIX shell command line
# --------------------------------------------------------------------------- #

# Characters that can break out of EITHER a bare/unquoted shell word OR an
# already-open single-quoted shell/sed literal (a sed program string, an
# echo/printf argument): a raw single quote closes an open '...' region;
# backtick/$ trigger command/variable substitution even mid-word; backslash
# has context-dependent escaping effects (and is sed's own escape char);
# ';' separates shell commands in a bare word; newlines/CR let a single
# logical command become several; NUL truncates C strings some tools use
# internally. Everything else (spaces, |, :, !, -, @, ~) stays available —
# every legitimate value observed in these templates (cipher-suite strings,
# pipe-separated extension lists, paths, IPs) only needs that punctuation,
# never any of the seven characters below.
_SHELL_BREAKOUT_CHARS: Sequence[str] = ("'", "`", "$", "\\", ";", "\n", "\r", "\x00")


def reject_shell_breakout_chars(value: object, field: str, *,
                                 extra: Iterable[str] = (),
                                 max_length: int = 4096) -> str:
    """
    Deny the small set of characters that can break out of a POSIX shell
    command line regardless of whether the substitution site is a bare
    unquoted word or already sits inside an open single-quoted region
    (both patterns appear across the mongodb/apache SSH hardening
    templates, sometimes for the same parameter in different commands).
    """
    value = str(value)
    _check_length(value, field, max_length)
    for ch in tuple(_SHELL_BREAKOUT_CHARS) + tuple(extra):
        if ch in value:
            _fail(field, f"contains unsupported character/sequence {ch!r}")
    return value


def quote_shell(value: object) -> str:
    """shlex.quote() for a value substituted into a bare shell word position."""
    return shlex.quote(str(value))


def escape_single_quoted_shell_literal(value: object, field: str, *,
                                        deny: Iterable[str] = (),
                                        max_length: int = 8192) -> str:
    """
    Escape a value for insertion into a position that sits *inside* an
    already-open single-quoted shell argument (not one this function opens
    itself — the template's own literal ``'`` characters bracket it).

    Some legitimate values genuinely need an embedded single quote — e.g. a
    MongoDB audit filter expression whose JSON strings are single-quoted by
    the documented convention in this codebase (``parameter_metadata.py``:
    "single quotes only — the value is wrapped in double quotes inside
    mongod.conf"), which conflicts with simply denying ``'`` outright.
    The standard POSIX trick embeds a literal single quote inside an
    open ``'...'`` string as ``'\\''``: close the quote, emit a
    backslash-escaped quote as a separate (unquoted) token, reopen the
    quote. Applied to every embedded ``'`` this makes the value's
    boundaries unambiguous to the shell regardless of content, closing
    the same breakout the strict denylist closes elsewhere — just via
    escaping instead of rejection, to keep this one legitimate format
    usable. NUL and any caller-supplied ``deny`` characters are still
    rejected outright since they have no safe escape here.
    """
    value = str(value)
    _check_length(value, field, max_length)
    if "\x00" in value:
        _fail(field, "contains a NUL byte")
    for ch in deny:
        if ch in value:
            _fail(field, f"contains unsupported character/sequence {ch!r}")
    return value.replace("'", "'\\''")


def reject_single_quoted_literal_breakout(value: object, field: str, *,
                                           extra: Iterable[str] = (),
                                           max_length: int = 4096) -> str:
    """
    Deny characters that can break out of a value substituted into a
    position that is *always* inside an existing single-quoted shell
    argument (never a bare word) — e.g. free-form JSON-like filter text
    wrapped in ``'...'`` for a ``sed ... a\\`` append. Single-quoted shell
    strings do not interpret ``$``, backticks, backslashes, or ``;`` at
    all, so — unlike ``reject_shell_breakout_chars`` — those stay
    available here; only the single quote itself (which closes the
    literal early) and line/NUL control characters are denied.
    """
    value = str(value)
    _check_length(value, field, max_length)
    for ch in ("'", "\n", "\r", "\x00") + tuple(extra):
        if ch in value:
            _fail(field, f"contains unsupported character/sequence {ch!r}")
    return value


# --------------------------------------------------------------------------- #
#  RESTRICTED CHARSETS — path / identifier / host-list allowlists
# --------------------------------------------------------------------------- #

def _restrict_to_charset(value: str, field: str, pattern: "re.Pattern[str]", *,
                          description: str, max_length: int) -> str:
    value = str(value)
    if not value:
        _fail(field, "must not be empty")
    _check_length(value, field, max_length)
    if not pattern.fullmatch(value):
        _fail(field, f"must contain only {description}")
    return value


_PATH_RE = re.compile(r"[A-Za-z0-9_./:-]+")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_-]+")
_HOST_LIST_RE = re.compile(r"[A-Za-z0-9_.:,-]+")


def validate_path(value: object, field: str, *, max_length: int = 255) -> str:
    """A filesystem path: letters, digits, ``. _ / : -`` only. Safe to insert
    unquoted into either a bare shell word or an existing quoted region,
    since nothing in the allowed charset is meaningful to a shell."""
    return _restrict_to_charset(
        str(value), field, _PATH_RE,
        description="letters, digits, '.', '_', '/', ':', '-'",
        max_length=max_length,
    )


def validate_identifier(value: object, field: str, *, max_length: int = 64) -> str:
    """A bare name (service/OS account, etc.): letters, digits, ``_ -`` only."""
    return _restrict_to_charset(
        str(value), field, _IDENTIFIER_RE,
        description="letters, digits, '_', '-'",
        max_length=max_length,
    )


def validate_host_list(value: object, field: str, *, max_length: int = 255) -> str:
    """One or more IPs/hostnames: letters, digits, ``. : , -`` only."""
    return _restrict_to_charset(
        str(value), field, _HOST_LIST_RE,
        description="letters, digits, '.', ':', ',', '-'",
        max_length=max_length,
    )


# --------------------------------------------------------------------------- #
#  POWERSHELL_SINGLE_Q — value inside an existing '...' PowerShell literal
# --------------------------------------------------------------------------- #

def escape_powershell_single_quoted(value: object, field: str, *,
                                     max_length: int = 1024) -> str:
    """
    Escape a value for insertion inside an existing PowerShell single-quoted
    string literal (``'...'``). PowerShell single-quoted strings do not
    interpret ``$`` or backticks — the only escape needed is doubling any
    embedded single quote, the sole character that could otherwise close
    the literal early.
    """
    value = str(value)
    _check_length(value, field, max_length)
    _reject_control_chars(value, field, allow_newlines=False)
    return value.replace("'", "''")


def validate_powershell_bare_integer(value: object, field: str, *,
                                      min_value: Optional[int] = None,
                                      max_value: Optional[int] = None) -> str:
    """A bare (unquoted) integer substituted directly into a PowerShell/
    native-command argument position, e.g. ``net accounts /maxpwage:{X}``.
    Validated as a plain integer and returned unmodified — a value that
    round-trips through ``int()`` cannot contain any PowerShell metacharacter."""
    return validate_integer(value, field, min_value=min_value, max_value=max_value)


# --------------------------------------------------------------------------- #
#  SQL_IDENTIFIER — value inside a T-SQL [bracket] or 'string' context
# --------------------------------------------------------------------------- #

_SQL_UNSAFE_CHARS: Sequence[str] = ("'", "]", ";", "\n", "\r")


def escape_sql_identifier_text(value: object, field: str, *, max_length: int = 128) -> str:
    """
    Validate a value inserted into a T-SQL statement as either a
    ``[bracket]``-quoted identifier or a ``'string'``-quoted literal (some
    MSSQL templates use the same placeholder in both contexts across their
    ``statements`` and ``verify_statements``). Denying every character that
    could close *either* delimiter — ``]``, ``'``, and the statement/line
    separators — is safe in both without needing to track which context a
    given substitution site uses.
    """
    value = str(value)
    _check_length(value, field, max_length)
    for ch in _SQL_UNSAFE_CHARS:
        if ch in value:
            _fail(field, f"contains unsupported character/sequence {ch!r}")
    if "--" in value:
        _fail(field, "contains unsupported character/sequence '--'")
    return value


# --------------------------------------------------------------------------- #
#  INTEGER / SELECT
# --------------------------------------------------------------------------- #

def validate_integer(value: object, field: str, *,
                      min_value: Optional[int] = None,
                      max_value: Optional[int] = None) -> str:
    """Validate a value is a plain base-10 integer, optionally range-bound,
    and return it normalized to ``str(int(value))``. A value that survives
    this check contains only ``[0-9]`` and an optional leading ``-``, so it
    cannot carry any shell/SQL/PowerShell/CLI metacharacter."""
    raw = str(value).strip()
    try:
        number = int(raw)
    except (TypeError, ValueError):
        _fail(field, f"'{raw}' is not a number")
        raise  # pragma: no cover - _fail always raises; satisfies type checkers
    if min_value is not None and number < min_value:
        _fail(field, f"{number} is below the minimum {min_value}")
    if max_value is not None and number > max_value:
        _fail(field, f"{number} is above the maximum {max_value}")
    return str(number)


def validate_select(value: object, field: str, options: Sequence[str]) -> str:
    """Validate a value is exactly one of a fixed set of allowed literals
    (an enum/select field). The frontend renders these as a dropdown, but
    the backend never enforced the option list — a direct API caller could
    submit anything, so this closes that gap for every module that uses it."""
    value = str(value)
    if value not in options:
        _fail(field, f"value '{value}' not in {list(options)}")
    return value
