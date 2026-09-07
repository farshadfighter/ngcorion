"""
SSH Client for Cisco Device Auditing

Handles SSH connections and command execution on Cisco IOS/IOS-XE devices.
Based on netmiko library with "turbo" command collection strategy.
"""

from contextlib import contextmanager
from typing import List, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import re
import time
import logging

# Import paramiko exceptions for algorithm/key errors
try:
    from paramiko.ssh_exception import (
        SSHException,
        BadHostKeyException,
        NoValidConnectionsError
    )
    from paramiko.transport import IncompatiblePeer
except ImportError:
    # Fallback if paramiko structure changes
    SSHException = Exception
    BadHostKeyException = Exception
    NoValidConnectionsError = Exception
    IncompatiblePeer = Exception

from app.core.ssh_exceptions import (
    SSHConnectionError,
    SSHAuthenticationError,
    SSHConnectionTimeoutError,
    SSHNetworkError,
    SSHAlgorithmMismatchError,
    SSHHostKeyError,
    map_ssh_exception
)
from app.core.ssh_host_keys import (
    classify_netmiko_auth_failure,
    ensure_host_key_trusted,
    netmiko_host_key_kwargs,
)

logger = logging.getLogger(__name__)

# Turbo Commands - Targeted snippets instead of full running-config
CISCO_TURBO_COMMANDS: List[str] = [
    # Identity / DNS
    "show run | i ^hostname|^ip domain-name|^no ip domain-lookup",

    # Access / Management (VTY/Console/Banners)
    "show run | sec line vty",
    "show run | sec line console",
    "show run | i ^banner motd|^banner login",

    # SSH hardening
    "show run | i ^ip ssh version|^ip ssh timeout|^ip ssh time-out|^ip ssh authentication-retries|^ip ssh server algorithm",
    "show ip ssh",

    # Service hygiene one-liners. These are default-state global services that
    # only appear in running-config once explicitly toggled (e.g. "no service
    # dhcp", "no ip identd", "service tcp-keepalives-in"). They MUST be grepped
    # explicitly — otherwise checks CIS-2.1.4/2.1.5/2.1.6 never see them and
    # report non-compliant even after hardening applies them. The positive
    # "ip bootp server"/"ip identd"/"service pad" forms are grepped too so the
    # disable-service checks (off-by-default, "no ..." suppressed) can still
    # detect a service that is explicitly ENABLED.
    "show run | i ^no service tcp-small-servers|^no service udp-small-servers|^no service dhcp|^no service pad|^no ip bootp server|^no ip finger|^no ip identd|^service tcp-keepalives|^ip bootp server|^ip identd|^service pad",

    # AAA / Login controls / Logging
    "show run | i ^aaa |^login block-for|^login on-failure|^login on-success",
    "show run | i ^service password-encryption|^service timestamps log datetime",
    # Grep EVERY "logging ..." line from running-config. The old narrow filter
    # (host|trap|buffered|facility) dropped lines like "logging source-interface"
    # (CIS-2.2.7) and "logging console" (CIS-2.2.3), so post-hardening verification
    # never saw them and reported FAIL even when the fix applied correctly.
    "show run | i ^logging ",
    # Operational logging state from "show logging". Some compliant values equal
    # the IOS default and are therefore suppressed from running-config — notably
    # "logging on" -> "Syslog logging: enabled" (CIS-2.2.1) and "logging trap
    # informational" -> "Trap logging: level informational" (CIS-2.2.5). Collect
    # just the summary lines, not the buffered message dump, so defaults verify.
    "show logging | i (Syslog|Console|Trap) logging",
    "show run | sec archive",
    "show archive",

    # SNMP
    "show run | i ^snmp-server ",

    # Users / enable (note: values may be masked later)
    "show run | i ^username |^enable password|^enable secret",

    # Time / NTP
    "show run | i ^clock timezone|^ntp ",

    # L2/L3 hygiene
    "show run | i ^no ip directed-broadcast|^no ip source-route|^no ip http ",
    "show run | i ^(no )?cdp run|^(no )?lldp run",

    # Interfaces evidence
    "show run | i ^interface ",
    "show run | i ip access-group ",
    "show run | i no ip proxy-arp",

    # Crypto key / boot / version evidences
    "show crypto key mypubkey rsa",
    "show version | i Configuration register|System image file is",

    # Secure boot / boot system
    "show run | i ^secure boot-(image|config)|^boot system",

    # CoPP evidence
    "show run | sec policy-map type control-plane",
]

# Subset of the turbo commands that surface data NOT already present in a full
# `show running-config`. Every "show run | include/section ..." entry above is a
# filtered view of running-config, so it is redundant for a caller that already
# holds the complete running-config (e.g. hardening verification). Only these
# operational/non-config show commands add information beyond running-config.
CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS: List[str] = [
    cmd for cmd in CISCO_TURBO_COMMANDS
    if not cmd.strip().lower().startswith("show run")
]

# Config commands that stop on an interactive question instead of returning to
# the config prompt. `crypto key generate rsa` is the important one: when the
# device already holds a keypair, IOS answers with
#   % You already have RSA keys defined named <name>.
#   % Do you really want to replace them? [yes/no]:
# and waits. send_config_set() never answers it, so the key was never replaced
# and the device kept its old (1024-bit) modulus — CIS 2.1.1.1.3 then verified
# FAIL no matter how often hardening ran.
CONFIRMATION_COMMANDS = re.compile(r"^\s*crypto key (?:generate|zeroize)\b", re.I)

# Interactive questions these commands ask, most specific first.
YES_NO_PROMPT = re.compile(r"\[yes/no\]\s*:?\s*$", re.I)
CONFIRM_PROMPT = re.compile(r"\[confirm\]\s*$", re.I)
# "How many bits in the modulus [512]:" — only asked when the command itself
# carried no "modulus <n>"; answering with the device default would create a
# 512-bit key, so the requested size is echoed back instead.
MODULUS_PROMPT = re.compile(r"how many bits in the modulus[^\n]*$", re.I)

# Redaction patterns for sensitive data
REDACT_PATTERNS = [
    # enable secret/password values
    (re.compile(r"^(enable secret)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(enable password)\s+.+$", re.M), r"\1 <REDACTED>"),

    # local users passwords/secrets
    (re.compile(r"^(username\s+\S+\s+password)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(username\s+\S+\s+secret)\s+.+$", re.M), r"\1 <REDACTED>"),

    # snmp community values
    (re.compile(r"^(snmp-server community)\s+\S+", re.M), r"\1 <REDACTED>"),

    # ntp authentication keys
    (re.compile(r"^(ntp authentication-key\s+\d+\s+md5)\s+\S+", re.M), r"\1 <REDACTED>"),

    # tacacs-server keys
    (re.compile(r"^(tacacs-server\s+host\s+\S+\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(tacacs-server\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),

    # radius-server keys
    (re.compile(r"^(radius-server\s+host\s+\S+\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(radius-server\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),

    # The audit dump is now the full running-config (not a narrow grep subset),
    # so it can contain secret-bearing lines the patterns above don't cover.
    # Checks run on the raw config, so these only mask the stored/displayed dump
    # and per-finding evidence — they never affect pass/fail.

    # routing-protocol key chains (EIGRP/RIP/OSPF auth) — "key-string [0|7] <key>"
    (re.compile(r"^(\s*key-string)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
    # generic line/interface passwords — "password [0|7] <value>" (NOT "enable
    # password" / "username ... password", which start with another keyword and
    # are handled above)
    (re.compile(r"^(\s*password)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
    # BGP neighbor MD5 password
    (re.compile(r"^(\s*neighbor\s+\S+\s+password)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
    # IKE/IPsec pre-shared keys
    (re.compile(r"^(\s*crypto isakmp key)\s+\S+", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(.*pre-shared-key.*\skey)\s+\S+", re.M), r"\1 <REDACTED>"),
    # PPP CHAP/PAP credentials
    (re.compile(r"^(\s*ppp chap password)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(\s*ppp pap sent-username\s+\S+\s+password)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
    # TFTP/FTP transfer credentials
    (re.compile(r"^(ip ftp password)\s+(?:\d+\s+)?.+$", re.M), r"\1 <REDACTED>"),
]


class CiscoSSHClient:
    """
    SSH client for Cisco IOS/IOS-XE devices.

    Handles connection, command execution, and cleanup with proper error handling.
    Includes retry logic for transient failures.
    """

    # Default retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    # Connection-wide read budget. netmiko's own reads (find_prompt,
    # check_config_mode, _test_channel_read) take no timeout argument and
    # default to 10s, which is what raises "Pattern not detected: '[>#]'" on
    # devices slow to echo a prompt. read_timeout_override is the only lever
    # that reaches those internal reads.
    READ_TIMEOUT = 30
    # Config pushes legitimately run longer than a single show command.
    CONFIG_READ_TIMEOUT = 120

    def __init__(self,
                 ip: str,
                 username: str,
                 password: str,
                 secret: Optional[str] = None,
                 port: int = 22,
                 device_type: str = "cisco_ios",
                 timeout: int = 30,
                 fast_cli: bool = True,
                 max_retries: int = 3):
        """
        Initialize SSH client parameters.

        Args:
            ip: Target device IP address
            username: SSH username
            password: SSH password
            secret: Enable secret (optional)
            port: SSH port (default 22)
            device_type: Netmiko device type (default: cisco_ios)
            timeout: Connection/command timeout in seconds
            fast_cli: Enable fast CLI mode (reduces delays)
            max_retries: Maximum number of connection retries
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.device_type = device_type
        self.timeout = timeout
        self.fast_cli = fast_cli
        self.max_retries = max_retries
        self.connection = None
        self._in_enable_mode = False

    def connect(self) -> None:
        """
        Establish SSH connection to device with retry logic.

        Raises:
            SSHAuthenticationError: If authentication fails
            SSHConnectionTimeoutError: If connection times out after all retries
            SSHNetworkError: If device is unreachable
            SSHAlgorithmMismatchError: If SSH algorithm negotiation fails
            SSHHostKeyError: If host key verification fails
            SSHConnectionError: For other SSH failures
        """
        last_exception = None

        # Verify (and, under the tofu policy, pin) the device's host key before
        # any credential — including the enable secret — is sent.
        ensure_host_key_trusted(self.ip, self.port, timeout=self.timeout)

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"SSH connection attempt {attempt}/{self.max_retries} to {self.ip}")

                self.connection = ConnectHandler(
                    device_type=self.device_type,
                    ip=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    secret=self.secret,
                    fast_cli=self.fast_cli,
                    timeout=self.timeout,
                    global_delay_factor=2,
                    session_timeout=60,
                    read_timeout_override=self.READ_TIMEOUT,
                    banner_timeout=20,  # Longer banner timeout for slow devices
                    auth_timeout=20,    # Longer auth timeout
                    **netmiko_host_key_kwargs(),
                )

                # Enter enable mode if needed/possible. Always check current state
                # first — if SSH auto-elevates to privilege 15 we're already at '#'.
                try:
                    if self._ensure_enable_mode():
                        logger.debug(f"In enable mode on {self.ip}")
                    else:
                        logger.info(
                            f"Not in enable mode on {self.ip}: no enable secret "
                            "provided (read-only commands will still work)"
                        )
                except Exception as e:
                    logger.warning(f"Failed to enter enable mode on {self.ip}: {e}")
                    # Continue — read-only show commands still work without enable mode

                # Disable paging
                try:
                    self.connection.send_command("terminal length 0", cmd_verify=False)
                except Exception as exc:
                    logger.warning(f"[Cisco SSH] could not disable paging on {self.ip}: {exc}")

                logger.info(f"Successfully connected to {self.ip}")
                return  # Success - exit retry loop

            except NetmikoAuthenticationException as e:
                # netmiko wraps every paramiko SSHException (BadHostKeyException,
                # RejectPolicy's "not found in known_hosts") in this type, so a
                # host-key failure must be separated out before it is reported
                # to the operator as a credential problem.
                host_key_error = classify_netmiko_auth_failure(e, self.ip)
                if host_key_error:
                    raise host_key_error
                # Don't retry on auth failures - credentials are wrong
                logger.error(f"Authentication failed for {self.ip}")
                raise SSHAuthenticationError(self.ip, original_error=e)

            except IncompatiblePeer as e:
                # Don't retry on algorithm mismatch - won't change
                logger.error(f"SSH algorithm mismatch with {self.ip}")
                raise SSHAlgorithmMismatchError(self.ip, original_error=e)

            except BadHostKeyException as e:
                # Don't retry on host key errors
                logger.error(f"Host key verification failed for {self.ip}")
                raise SSHHostKeyError(self.ip, original_error=e)

            except NoValidConnectionsError as e:
                # Don't retry on connection refused - service not available
                logger.error(f"Connection refused by {self.ip}")
                raise SSHNetworkError(self.ip, original_error=e)

            except NetmikoTimeoutException as e:
                last_exception = e
                logger.warning(f"Connection timeout to {self.ip} (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except OSError as e:
                # Socket-level errors - check if retryable
                if hasattr(e, 'errno') and e.errno in (111, 113):  # Connection refused, No route
                    logger.error(f"Network error connecting to {self.ip}: {e}")
                    raise SSHNetworkError(self.ip, original_error=e)
                # Other OS errors - retry
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except Exception as e:
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        # All retries exhausted - map the last exception to appropriate type
        error_msg = f"Failed to connect to {self.ip} after {self.max_retries} attempts"
        logger.error(error_msg)
        if last_exception:
            raise map_ssh_exception(last_exception, self.ip)
        else:
            raise SSHConnectionError(
                message=error_msg,
                device_ip=self.ip,
                suggestions=["Check network connectivity to the device"],
                original_error=None
            )

    def is_connected(self) -> bool:
        """Check if the SSH connection is still active."""
        if not self.connection:
            return False
        try:
            return self.connection.is_alive()
        except Exception:
            return False

    @contextmanager
    def _read_budget(self, seconds: float):
        """
        Temporarily widen the connection-wide read budget.

        ``read_timeout_override`` is a hard override: netmiko applies it to
        every read, including a ``read_timeout=`` passed to send_command or
        send_config_set. Without lifting it here, the longer config-push budget
        would be silently clamped down to READ_TIMEOUT.
        """
        prev = self.connection.read_timeout_override
        self.connection.read_timeout_override = seconds
        try:
            yield
        finally:
            self.connection.read_timeout_override = prev

    def _prompt_kwargs(self) -> dict:
        """
        Reuse the prompt netmiko captured at login instead of re-deriving it
        on every command.

        Each send_command() otherwise calls find_prompt(), and that read is
        what raises "Pattern not detected: '[>#]'" when a device is slow to
        echo a bare newline. base_prompt is set once by session_preparation and
        is stable for the session, so anchoring to it drops the per-command
        round trip that was failing.

        Falls back to netmiko's default when base_prompt is empty: an empty
        expect pattern matches immediately and would truncate every response.
        """
        if getattr(self.connection, "base_prompt", ""):
            return {"auto_find_prompt": False}
        return {}

    def _ensure_enable_mode(self) -> bool:
        """
        Ensure the session is in privileged (enable) mode.

        Returns:
            True if the session is in enable mode; False if it could not be
            entered because no enable secret is available.

        Raises:
            Propagates netmiko errors when an enable secret was provided but the
            elevation failed (e.g. wrong secret).

        Note on fast_cli: the enable password exchange is run with fast_cli
        temporarily disabled. fast_cli's aggressive timing can make netmiko read
        the channel before the device's "Password:" prompt — or the post-secret
        "#" prompt — is fully received, so it either never sends the secret or
        wrongly concludes elevation failed. That surfaces the misleading
        "Failed to enter enable mode. Please ensure you pass the 'secret'
        argument to ConnectHandler." error even when the secret is correct.
        Disabling fast_cli for just this exchange makes it reliable without
        slowing the bulk "show" collection.
        """
        if self._in_enable_mode:
            return True

        prev_fast_cli = self.connection.fast_cli
        self.connection.fast_cli = False
        try:
            # Already privileged? SSH users configured for privilege 15 land at
            # '#' without any enable step. Run this check with fast_cli disabled
            # too — under fast_cli it can misread a privileged session as
            # unprivileged and trigger a needless (and failing) enable attempt.
            if self.connection.check_enable_mode():
                self._in_enable_mode = True
                return True

            if not self.secret:
                return False

            self.connection.enable()
            self._in_enable_mode = True
            return True
        finally:
            self.connection.fast_cli = prev_fast_cli

    def collect_turbo(self, commands: Optional[List[str]] = None) -> str:
        """
        Collect targeted command outputs (Turbo mode).

        Args:
            commands: Optional explicit list of show commands to run. Defaults to
                the full CISCO_TURBO_COMMANDS set (used by audits). Callers that
                already hold a full running-config (e.g. hardening verification)
                can pass CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS to skip the
                redundant "show run | ..." views and run far fewer commands.

        Returns:
            str: Concatenated command outputs

        Raises:
            RuntimeError: If not connected
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        turbo_commands = commands if commands is not None else CISCO_TURBO_COMMANDS
        chunks: List[str] = []
        failed_commands = 0
        total_commands = len(turbo_commands)

        for cmd in turbo_commands:
            try:
                out = self.connection.send_command(
                    cmd,
                    cmd_verify=False,
                    read_timeout=self.READ_TIMEOUT,  # Per-command timeout
                    **self._prompt_kwargs()
                )
                chunks.append(f"!! {cmd}\n{out}\n")
            except Exception as e:
                failed_commands += 1
                error_msg = str(e)
                # Truncate very long error messages
                if len(error_msg) > 200:
                    error_msg = error_msg[:200] + "..."
                chunks.append(f"!! {cmd}\n<<ERROR: {type(e).__name__}: {error_msg}>>\n")
                logger.warning(f"Command failed on {self.ip}: {cmd[:50]}... - {type(e).__name__}")

        # Log summary
        success_rate = ((total_commands - failed_commands) / total_commands) * 100 if total_commands else 0
        logger.info(f"Turbo collection on {self.ip}: {total_commands - failed_commands}/{total_commands} commands succeeded ({success_rate:.1f}%)")

        return "\n".join(chunks).strip()

    def collect_config_dump(self) -> str:
        """
        Collect the evidence dump that CIS checks evaluate against.

        Returns the FULL "show running-config" plus the supplemental show
        commands whose data does NOT appear in running-config (RSA key size,
        "show ip ssh", "show logging" summary, "show version", "show archive").

        This is the single source of truth shared by the audit engine and by
        hardening verification. They previously diverged: the audit used the
        narrow "show run | include/section ..." turbo greps while verification
        used the full running-config. Any config line captured by one view but
        not the other made a freshly-hardened check verify PASS yet re-audit
        FAIL (e.g. "banner exec", "service timestamps debug", interface
        sub-commands such as "ip verify unicast", "ip access-list ...") and made
        protocol checks whose trigger line ("router eigrp/ospf/bgp") was never
        grepped report a vacuous PASS. Collecting the same full dump on both
        sides keeps audit and verify results identical.

        Using one "show running-config" plus ~5 supplemental commands is also
        fewer SSH round-trips than the ~25 turbo greps it replaces.

        Returns:
            str: running-config followed by supplemental show output

        Raises:
            RuntimeError: If not connected
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")
        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        running_config = self.send_command("show running-config")
        supplemental = self.collect_turbo(CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS)
        return f"{running_config}\n{supplemental}"

    def send_command(self, command: str, timeout: int = 30) -> str:
        """
        Send a single command to the device and return output.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            str: Command output

        Raises:
            RuntimeError: If not connected
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        try:
            output = self.connection.send_command(
                command,
                cmd_verify=False,
                read_timeout=timeout,
                **self._prompt_kwargs()
            )
            return output
        except Exception as e:
            logger.error(f"Command execution failed on {self.ip}: {command} - {str(e)}")
            raise RuntimeError(f"Command execution failed: {str(e)}")

    # Maximum interactive questions answered for a single command; a device
    # that keeps asking is a loop, not a prompt sequence.
    MAX_CONFIRMATIONS = 5

    @staticmethod
    def _confirmation_answer(output: str, command: str) -> Optional[str]:
        """
        Return the reply for the question at the end of ``output``, if any.

        Args:
            output: What the device has printed so far.
            command: The command that triggered the question — the modulus
                     prompt is answered with the size the command asked for.

        Returns:
            The text to send, or None when the device is not waiting on an
            answer (the tail is a prompt or ordinary output).
        """
        tail = output.rstrip()[-200:]
        if MODULUS_PROMPT.search(tail):
            m = re.search(r"\bmodulus\s+(\d+)", command, re.I)
            return m.group(1) if m else "2048"
        if YES_NO_PROMPT.search(tail):
            return "yes"
        if CONFIRM_PROMPT.search(tail):
            return ""  # bare newline confirms
        return None

    def _send_interactive_config_command(self, command: str) -> str:
        """
        Run one config command that asks interactive questions, answering them.

        Timing-based reads are used rather than prompt detection: the device is
        deliberately NOT at a prompt while it is asking, and RSA generation then
        pauses for tens of seconds before printing "[OK]".

        Args:
            command: Single configuration command

        Returns:
            str: Full transcript including the questions and the answers sent
        """
        if not self.connection.check_config_mode():
            self.connection.config_mode()

        read_kwargs = dict(
            strip_prompt=False,
            strip_command=False,
            read_timeout=self.CONFIG_READ_TIMEOUT,
            last_read=5.0,
        )

        output = self.connection.send_command_timing(command, **read_kwargs)
        for _ in range(self.MAX_CONFIRMATIONS):
            answer = self._confirmation_answer(output, command)
            if answer is None:
                break
            logger.info(
                f"Answering device confirmation for '{command}' on {self.ip} "
                f"with {answer!r}"
            )
            output += self.connection.send_command_timing(answer, **read_kwargs)

        # Key generation can stay silent well past the timing read; wait for the
        # config prompt so the next command is not typed into a busy channel.
        if self._confirmation_answer(output, command) is None:
            try:
                output += self.connection.read_until_pattern(
                    pattern=r"[>#]", read_timeout=self.CONFIG_READ_TIMEOUT
                )
            except Exception:
                pass  # already back at the prompt; nothing left to read

        return output

    def send_config_commands(self, commands: List[str]) -> str:
        """
        Send configuration commands to device using netmiko's send_config_set().

        This method automatically:
        - Enters configuration mode
        - Executes all commands
        - Exits configuration mode
        - Returns combined output

        Args:
            commands: List of configuration commands

        Returns:
            str: Combined output from all commands

        Raises:
            RuntimeError: If not connected or commands fail

        Example:
            >>> client.send_config_commands([
            ...     "hostname Router1",
            ...     "ip domain-name example.com"
            ... ])
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        try:
            # Ensure we're in enable mode before entering config mode. The helper
            # checks the actual device privilege state first (SSH sessions at
            # privilege 15 are already at '#') and runs the enable exchange with
            # fast_cli disabled so a correct secret is not rejected over timing.
            if not self._in_enable_mode:
                try:
                    entered = self._ensure_enable_mode()
                except Exception as e:
                    raise RuntimeError(
                        "Cannot enter configuration mode: enable mode "
                        "authentication failed. Verify the enable secret is "
                        "correct for this device."
                    ) from e
                if not entered:
                    raise RuntimeError(
                        "Cannot enter configuration mode: device is not in "
                        "privileged mode and no enable secret was provided."
                    )

            # Expand any commands that contain embedded newlines (e.g. banner templates)
            # into separate list items so send_config_set handles them line-by-line.
            expanded: list = []
            for cmd in commands:
                lines = cmd.split("\n")
                expanded.extend(lines)

            # Regex pattern for commands that may produce interactive prompts
            # (confirmation questions). Netmiko uses timing for these instead of
            # prompt detection, preventing "Pattern not detected: [>#]" errors.
            interactive_pattern = (
                r"^crypto key generate"
                r"|^banner\s+(exec|login|motd|incoming|slip-ppp)"
                r"|^no\s+interface\s+Tunnel"
            )

            # Commands that ask a question are executed one at a time by
            # _send_interactive_config_command, which answers it. Everything
            # else is batched through send_config_set as before. Order is
            # preserved so a sequence that mixes the two still applies in the
            # order the template wrote it.
            with self._read_budget(self.CONFIG_READ_TIMEOUT):
                outputs: list = []
                batch: list = []

                def flush_batch() -> None:
                    if not batch:
                        return
                    outputs.append(self.connection.send_config_set(
                        list(batch),
                        exit_config_mode=False,
                        cmd_verify=False,
                        read_timeout=self.CONFIG_READ_TIMEOUT,
                        delay_factor=2.0,
                        bypass_commands=interactive_pattern,
                    ))
                    batch.clear()

                for cmd in expanded:
                    if CONFIRMATION_COMMANDS.match(cmd):
                        flush_batch()
                        outputs.append(self._send_interactive_config_command(cmd))
                    else:
                        batch.append(cmd)
                flush_batch()

                self.connection.exit_config_mode()
                output = "\n".join(outputs)

            logger.info(f"Successfully executed {len(commands)} config commands on {self.ip}")
            return output

        except RuntimeError:
            # Re-raise RuntimeErrors directly (enable mode failures, etc.)
            raise
        except Exception as e:
            logger.error(f"Config command execution failed on {self.ip}: {str(e)}")
            raise RuntimeError(f"Config command execution failed: {str(e)}")

    def close(self) -> None:
        """Alias for disconnect() for compatibility."""
        self.disconnect()

    def disconnect(self) -> None:
        """Disconnect from device."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception as e:
                logger.warning(f"[Cisco SSH] disconnect from {self.ip} failed: {e}")
            finally:
                self.connection = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


def redact_sensitive_data(text: str) -> str:
    """
    Redact sensitive information from command outputs.

    Args:
        text: Raw command output text

    Returns:
        str: Text with sensitive data masked
    """
    result = text
    for pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
