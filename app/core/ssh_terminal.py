"""
Terminal sequences some Linux shells write around every prompt.

systemd 257 and later (Ubuntu 25.04+, Debian 13, Fedora 42+) installs
/etc/profile.d/80-systemd-osc-context.sh, which wraps every prompt and every
command in OSC 3008 "context" sequences, each with a new random ID; terminal
integrations (OSC 7 working directory, OSC 133 prompt marks) do the same.
netmiko strips only the CSI codes (colours, cursor moves), so it took these
sequences for part of the prompt, and a prompt with a new ID every time never
matched again: every command failed with "Pattern not detected".
"""

import re

# ESC ] ... ended by BEL or by ESC \ (the string terminator)
OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip_osc(text: str) -> str:
    """The text without OSC sequences."""
    return OSC.sub("", text) if isinstance(text, str) and "\x1b]" in text else text


def steady_prompt(conn) -> None:
    """Make an open netmiko connection drop OSC sequences from everything it reads, and read the prompt
    again when they had got into it."""
    plain = getattr(conn, "strip_ansi_escape_codes", None)
    if not callable(plain):
        return
    conn.strip_ansi_escape_codes = lambda text: plain(strip_osc(text))
    base = getattr(conn, "base_prompt", None)
    if isinstance(base, str) and "\x1b" in base:
        conn.set_base_prompt()
