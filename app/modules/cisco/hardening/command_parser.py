"""
Remediation Command Parser

Parses CIS rule remediation strings into executable command lists.

Handles various remediation patterns:
- "Configure: <command>" → Single command
- "Remove 'X' and configure 'Y'" → Multiple commands
- "Configure '<cmd>' on console and all VTYs" → Multi-context commands
- Template-based commands for common checks
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from .command_templates import has_template, get_template


@dataclass
class ParsedRemediation:
    """
    Parsed remediation result.

    Attributes:
        commands: List of CLI commands to execute
        requires_config_mode: Whether commands need config mode
        required_parameters: Parameters that must be provided
        optional_parameters: Parameters with defaults
        defaults: Default values for optional parameters
        warnings: Safety warnings for the user
    """
    commands: List[str]
    requires_config_mode: bool
    required_parameters: List[str]
    optional_parameters: List[str]
    defaults: Dict[str, str]
    warnings: List[str]


# Value constraints a parameter must satisfy for the resulting command to
# actually satisfy its CIS control. Without this, MODULUS=1024 substitutes
# cleanly, the device happily generates a 1024-bit key, and the check that
# asked for the fix still fails afterwards.
MINIMUM_PARAMETER_VALUES: Dict[str, Tuple[int, str]] = {
    "MODULUS": (
        2048,
        "CIS requires an RSA key of at least 2048 bits for SSH",
    ),
}


def validate_parameter_values(parameters: Dict[str, str]) -> None:
    """
    Raise if a numeric parameter is below the minimum its control requires.

    Args:
        parameters: Parameter values about to be substituted

    Raises:
        ValueError: If a value is non-numeric or below the required minimum
    """
    for name, (minimum, reason) in MINIMUM_PARAMETER_VALUES.items():
        if name not in parameters or parameters[name] is None:
            continue
        raw = str(parameters[name]).strip()
        if not raw:
            continue
        if not raw.isdigit():
            raise ValueError(f"{name} must be a number, got '{raw}'")
        if int(raw) < minimum:
            raise ValueError(
                f"{name} must be at least {minimum} ({reason}), got {raw}"
            )


class RemediationParser:
    """Parser for CIS remediation strings."""

    # Regex patterns for parameter extraction
    PARAM_PATTERN = re.compile(r'<([A-Z_][A-Z0-9_]*)>')  # Matches <PARAM_NAME>
    PLACEHOLDER_PATTERN = re.compile(r'\{([A-Z_][A-Z0-9_]*)\}')  # Matches {PARAM_NAME}

    # Command patterns
    CONFIGURE_PATTERN = re.compile(r'Configure:\s*(.+)', re.IGNORECASE)
    REMOVE_AND_CONFIGURE_PATTERN = re.compile(
        r"Remove\s+'([^']+)'\s+and\s+configure\s+'([^']+)'",
        re.IGNORECASE
    )
    DISABLE_PATTERN = re.compile(r'Disable:\s*(.+)', re.IGNORECASE)

    # Config mode commands (need "configure terminal")
    CONFIG_MODE_COMMANDS = {
        'hostname', 'ip', 'banner', 'line', 'aaa', 'service', 'enable',
        'ntp', 'logging', 'snmp-server', 'username', 'interface', 'router',
        'access-list', 'no cdp', 'no lldp', 'clock', 'archive', 'key',
    }

    @staticmethod
    def parse_remediation(
        remediation: str,
        check_number: str
    ) -> ParsedRemediation:
        """
        Parse remediation string into structured command list.

        Args:
            remediation: Remediation text from CIS rule
            check_number: CIS check number (e.g., "IOS-L1-001")

        Returns:
            ParsedRemediation object with commands and metadata

        Raises:
            ValueError: If remediation cannot be parsed
        """
        # First, check if we have a static template for this check
        if has_template(check_number):
            template = get_template(check_number)
            return ParsedRemediation(
                commands=template["commands"],
                requires_config_mode=template["config_mode"],
                required_parameters=template["required_params"],
                optional_parameters=template.get("optional_params", []),
                defaults=template.get("defaults", {}),
                warnings=template.get("warnings", [])
            )

        # No template - parse the remediation string dynamically
        return RemediationParser._parse_dynamic(remediation)

    @staticmethod
    def _parse_dynamic(remediation: str) -> ParsedRemediation:
        """
        Parse remediation string dynamically (no template available).

        Args:
            remediation: Remediation text

        Returns:
            ParsedRemediation object
        """
        commands = []
        warnings = []

        # Pattern 1: "Remove 'X' and configure 'Y'"
        match = RemediationParser.REMOVE_AND_CONFIGURE_PATTERN.search(remediation)
        if match:
            remove_cmd = match.group(1)
            configure_cmd = match.group(2)
            commands = [
                "configure terminal",
                f"no {remove_cmd}",
                configure_cmd,
                "end",
                "write memory"
            ]
            warnings.append(f"This will remove '{remove_cmd}' from configuration")

        # Pattern 2: "Configure: <command>"
        elif RemediationParser.CONFIGURE_PATTERN.search(remediation):
            match = RemediationParser.CONFIGURE_PATTERN.search(remediation)
            cmd = match.group(1).strip()
            commands = [
                "configure terminal",
                cmd,
                "end",
                "write memory"
            ]

        # Pattern 3: "Disable: <service>"
        elif RemediationParser.DISABLE_PATTERN.search(remediation):
            match = RemediationParser.DISABLE_PATTERN.search(remediation)
            service = match.group(1).strip()
            commands = [
                "configure terminal",
                f"no {service}",
                "end",
                "write memory"
            ]

        # Fallback: Treat entire remediation as a command
        else:
            # Extract actual command if it's in quotes
            quoted_match = re.search(r"'([^']+)'", remediation)
            if quoted_match:
                cmd = quoted_match.group(1)
                commands = [
                    "configure terminal",
                    cmd,
                    "end",
                    "write memory"
                ]
            else:
                raise ValueError(
                    f"Unable to parse remediation: {remediation}. "
                    "No template available and pattern not recognized."
                )

        # Extract parameters
        all_commands_text = "\n".join(commands)
        required_params = RemediationParser.extract_parameters(all_commands_text)

        # Detect if config mode is needed
        requires_config_mode = RemediationParser.detect_config_mode_needed(commands)

        return ParsedRemediation(
            commands=commands,
            requires_config_mode=requires_config_mode,
            required_parameters=required_params,
            optional_parameters=[],
            defaults={},
            warnings=warnings
        )

    @staticmethod
    def extract_parameters(text: str) -> List[str]:
        """
        Extract parameter placeholders from text.

        Supports both formats:
        - <PARAM_NAME> (angle brackets)
        - {PARAM_NAME} (curly braces)

        Args:
            text: Text containing parameters

        Returns:
            List of unique parameter names

        Examples:
            >>> extract_parameters("enable secret <STRONG_SECRET>")
            ['STRONG_SECRET']

            >>> extract_parameters("timeout {MIN} {SEC}")
            ['MIN', 'SEC']
        """
        params = set()

        # Find angle bracket parameters: <PARAM>
        params.update(RemediationParser.PARAM_PATTERN.findall(text))

        # Find curly brace parameters: {PARAM}
        params.update(RemediationParser.PLACEHOLDER_PATTERN.findall(text))

        return sorted(list(params))

    @staticmethod
    def substitute_parameters(
        commands: List[str],
        parameters: Dict[str, str]
    ) -> List[str]:
        """
        Replace parameter placeholders with actual values.

        Supports both formats:
        - <PARAM_NAME> → value
        - {PARAM_NAME} → value

        Args:
            commands: List of commands with placeholders
            parameters: Dict mapping parameter names to values

        Returns:
            List of commands with placeholders replaced

        Raises:
            ValueError: If required parameter is missing

        Examples:
            >>> substitute_parameters(
            ...     ["enable secret {STRONG_SECRET}"],
            ...     {"STRONG_SECRET": "MyPass123"}
            ... )
            ['enable secret MyPass123']
        """
        # Reject values that would produce a command the CIS control cannot
        # accept, before anything is sent to the device.
        validate_parameter_values(parameters)

        result = []

        for cmd in commands:
            # Check for required parameters. A placeholder that is absent OR
            # present-but-blank is treated as missing — substituting "" would
            # emit a malformed command (e.g. "logging source-interface " or
            # "enable secret ") that configures nothing yet appears to succeed.
            required_params = RemediationParser.extract_parameters(cmd)
            missing_params = [
                p for p in required_params
                if p not in parameters
                or (isinstance(parameters[p], str) and parameters[p].strip() == "")
                or parameters[p] is None
            ]

            if missing_params:
                raise ValueError(
                    f"Missing required parameters: {', '.join(missing_params)}"
                )

            # Replace parameters
            substituted = cmd
            for param_name, param_value in parameters.items():
                # Replace both formats
                substituted = substituted.replace(f"<{param_name}>", param_value)
                substituted = substituted.replace(f"{{{param_name}}}", param_value)

            result.append(substituted)

        return result

    @staticmethod
    def detect_config_mode_needed(commands: List[str]) -> bool:
        """
        Detect if commands require configuration mode.

        Args:
            commands: List of commands

        Returns:
            True if any command requires config mode

        Examples:
            >>> detect_config_mode_needed(["hostname Router1"])
            True

            >>> detect_config_mode_needed(["show running-config"])
            False
        """
        # Commands that explicitly enter/exit config mode
        if "configure terminal" in commands or "config t" in commands:
            return True

        # Check if any command starts with known config mode keywords
        for cmd in commands:
            cmd_lower = cmd.lower().strip()

            # Skip meta commands
            if cmd_lower in ["end", "exit", "write memory", "copy running-config startup-config"]:
                continue

            # Check against known config mode command prefixes
            for prefix in RemediationParser.CONFIG_MODE_COMMANDS:
                if cmd_lower.startswith(prefix):
                    return True

        return False

    @staticmethod
    def validate_cisco_syntax(commands: List[str]) -> Tuple[bool, List[str]]:
        """
        Basic validation of Cisco command syntax.

        Args:
            commands: List of commands to validate

        Returns:
            Tuple of (is_valid, list_of_errors)

        Note:
            This is a basic syntax check, not a full validation.
            Actual validation happens when commands are sent to device.
        """
        errors = []

        # Check for empty commands
        if not commands:
            errors.append("No commands provided")
            return False, errors

        for i, cmd in enumerate(commands, 1):
            cmd_stripped = cmd.strip()

            # Check for empty lines
            if not cmd_stripped:
                errors.append(f"Line {i}: Empty command")
                continue

            # Check for dangerous commands (should not be in auto-remediation)
            dangerous_keywords = [
                "reload", "erase", "format", "delete", "clear config"
            ]
            if any(keyword in cmd_stripped.lower() for keyword in dangerous_keywords):
                errors.append(f"Line {i}: Dangerous command detected: {cmd_stripped}")

            # Check for shell/escape sequences
            if any(char in cmd_stripped for char in [';', '|', '&', '\n', '\r', '!']):
                # Exception: "!" is used for ACL deny/permit statements
                if cmd_stripped.startswith("!"):
                    continue
                errors.append(f"Line {i}: Invalid characters detected: {cmd_stripped}")

        return len(errors) == 0, errors


def apply_defaults(
    parameters: Dict[str, str],
    defaults: Dict[str, str]
) -> Dict[str, str]:
    """
    Apply default values to parameters.

    Args:
        parameters: User-provided parameters
        defaults: Default values

    Returns:
        Combined parameters with defaults applied

    A blank/whitespace-only user value must NOT override a real template default.
    An empty optional field (e.g. SOURCE_INTERFACE left blank in the UI) would
    otherwise substitute to "" and send a broken command such as
    "logging source-interface " with no interface — which configures nothing on
    the device and then fails verification.

    Example:
        >>> apply_defaults(
        ...     {"TIMEOUT_MIN": "10"},
        ...     {"TIMEOUT_MIN": "5", "TIMEOUT_SEC": "0"}
        ... )
        {'TIMEOUT_MIN': '10', 'TIMEOUT_SEC': '0'}

        >>> apply_defaults(
        ...     {"SOURCE_INTERFACE": ""},
        ...     {"SOURCE_INTERFACE": "Loopback0"}
        ... )
        {'SOURCE_INTERFACE': 'Loopback0'}
    """
    result = defaults.copy()
    for key, value in parameters.items():
        # Skip None and blank strings when a non-empty default exists, so an
        # empty optional field falls back to the template default instead of
        # clobbering it with "".
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "" and str(defaults.get(key, "")).strip() != "":
            continue
        result[key] = value
    return result
