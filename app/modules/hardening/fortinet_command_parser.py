"""
FortiGate Remediation Command Parser

Parses FortiGate rule remediation strings into executable command lists.

FortiGate uses hierarchical config blocks:
- config <section>
- set <key> <value>
- edit <object>
- end

Handles various remediation patterns and template-based commands.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from .fortinet_command_templates import has_fortigate_template, get_fortigate_template


@dataclass
class FortiGateParsedRemediation:
    """
    Parsed FortiGate remediation result.

    Attributes:
        commands: List of CLI commands to execute
        required_parameters: Parameters that must be provided
        optional_parameters: Parameters with defaults
        defaults: Default values for optional parameters
        warnings: Safety warnings for the user
        vdom_context: Whether this is global or per-VDOM ("global" or "vdom")
    """
    commands: List[str]
    required_parameters: List[str]
    optional_parameters: List[str]
    defaults: Dict[str, str]
    warnings: List[str]
    vdom_context: str = "global"


class FortiGateRemediationParser:
    """Parser for FortiGate remediation strings."""

    # Regex patterns for parameter extraction
    PARAM_PATTERN = re.compile(r'<([A-Z_][A-Z0-9_]*)>')  # Matches <PARAM_NAME>
    PLACEHOLDER_PATTERN = re.compile(r'\{([A-Z_][A-Z0-9_]*)\}')  # Matches {PARAM_NAME}

    # FortiGate config block patterns
    CONFIG_START_PATTERN = re.compile(r'^config\s+', re.IGNORECASE)
    EDIT_PATTERN = re.compile(r'^edit\s+', re.IGNORECASE)
    END_PATTERN = re.compile(r'^end\s*$', re.IGNORECASE)

    @staticmethod
    def parse_remediation(
        remediation: str,
        check_id: str
    ) -> FortiGateParsedRemediation:
        """
        Parse remediation string into structured command list.

        Args:
            remediation: Remediation text from FortiGate control
            check_id: FortiGate check ID (e.g., "FG-BL-001")

        Returns:
            FortiGateParsedRemediation object with commands and metadata

        Raises:
            ValueError: If remediation cannot be parsed
        """
        # First, check if we have a static template for this check
        if has_fortigate_template(check_id):
            template = get_fortigate_template(check_id)
            return FortiGateParsedRemediation(
                commands=template["commands"],
                required_parameters=template["required_params"],
                optional_parameters=template.get("optional_params", []),
                defaults=template.get("defaults", {}),
                warnings=template.get("warnings", []),
                vdom_context=template.get("vdom_context", "global")
            )

        # No template - parse the remediation string dynamically
        return FortiGateRemediationParser._parse_dynamic(remediation)

    @staticmethod
    def _parse_dynamic(remediation: str) -> FortiGateParsedRemediation:
        """
        Parse remediation string dynamically (no template available).

        FortiGate remediation format examples:
        - "config system global\\n set admin-https enable\\nend"
        - "config system password-policy\\n set status enable\\nend"

        Args:
            remediation: Remediation text

        Returns:
            FortiGateParsedRemediation object
        """
        commands = []
        warnings = []

        # Split by \\n (literal backslash-n in the remediation string)
        if "\\n" in remediation:
            commands = [cmd.strip() for cmd in remediation.split("\\n") if cmd.strip()]
        # Also try actual newlines
        elif "\n" in remediation:
            commands = [cmd.strip() for cmd in remediation.split("\n") if cmd.strip()]
        else:
            # Single line remediation
            commands = [remediation.strip()]

        if not commands:
            raise ValueError(
                f"Unable to parse FortiGate remediation: {remediation}. "
                "No commands found."
            )

        # Extract parameters
        all_commands_text = "\n".join(commands)
        params = FortiGateRemediationParser.extract_parameters(all_commands_text)

        # Determine VDOM context based on config section
        vdom_context = "global"
        for cmd in commands:
            if re.match(r'config\s+vpn\s+', cmd, re.IGNORECASE):
                vdom_context = "vdom"
                break
            if re.match(r'config\s+firewall\s+', cmd, re.IGNORECASE):
                vdom_context = "vdom"
                break

        return FortiGateParsedRemediation(
            commands=commands,
            required_parameters=params,
            optional_parameters=[],
            defaults={},
            warnings=warnings,
            vdom_context=vdom_context
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
            >>> extract_parameters("set admintimeout {ADMIN_TIMEOUT}")
            ['ADMIN_TIMEOUT']

            >>> extract_parameters("set server <NTP_SERVER>")
            ['NTP_SERVER']
        """
        params = set()

        # Find angle bracket parameters: <PARAM>
        params.update(FortiGateRemediationParser.PARAM_PATTERN.findall(text))

        # Find curly brace parameters: {PARAM}
        params.update(FortiGateRemediationParser.PLACEHOLDER_PATTERN.findall(text))

        return sorted(list(params))

    @staticmethod
    def substitute_parameters(
        commands: List[str],
        parameters: Dict[str, str]
    ) -> List[str]:
        """
        Replace parameter placeholders with actual values.

        Supports both formats:
        - <PARAM_NAME> -> value
        - {PARAM_NAME} -> value

        Args:
            commands: List of commands with placeholders
            parameters: Dict mapping parameter names to values

        Returns:
            List of commands with placeholders replaced

        Raises:
            ValueError: If required parameter is missing

        Examples:
            >>> substitute_parameters(
            ...     ["set admintimeout {ADMIN_TIMEOUT}"],
            ...     {"ADMIN_TIMEOUT": "10"}
            ... )
            ['set admintimeout 10']
        """
        result = []

        for cmd in commands:
            # Check for required parameters
            required_params = FortiGateRemediationParser.extract_parameters(cmd)
            missing_params = [p for p in required_params if p not in parameters]

            if missing_params:
                raise ValueError(
                    f"Missing required parameters: {', '.join(missing_params)}"
                )

            # Replace parameters
            substituted = cmd
            for param_name, param_value in parameters.items():
                # Replace both formats
                substituted = substituted.replace(f"<{param_name}>", str(param_value))
                substituted = substituted.replace(f"{{{param_name}}}", str(param_value))

            result.append(substituted)

        return result

    @staticmethod
    def validate_fortigate_syntax(commands: List[str]) -> Tuple[bool, List[str]]:
        """
        Basic validation of FortiGate command syntax.

        Checks for:
        - Empty commands
        - Dangerous commands
        - Unclosed config blocks
        - Invalid characters

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

        # Track config block depth
        config_depth = 0

        for i, cmd in enumerate(commands, 1):
            cmd_stripped = cmd.strip()

            # Check for empty lines
            if not cmd_stripped:
                errors.append(f"Line {i}: Empty command")
                continue

            # Track config blocks
            if re.match(r'^config\s+', cmd_stripped, re.IGNORECASE):
                config_depth += 1
            elif re.match(r'^edit\s+', cmd_stripped, re.IGNORECASE):
                pass  # Edit doesn't change depth
            elif re.match(r'^end\s*$', cmd_stripped, re.IGNORECASE):
                config_depth -= 1
                if config_depth < 0:
                    errors.append(f"Line {i}: Unexpected 'end' - no matching config block")

            # Check for dangerous commands
            dangerous_keywords = [
                "execute reboot",
                "execute shutdown",
                "execute factoryreset",
                "execute formatlogdisk",
                "execute restore"
            ]
            cmd_lower = cmd_stripped.lower()
            if any(keyword in cmd_lower for keyword in dangerous_keywords):
                errors.append(f"Line {i}: Dangerous command detected: {cmd_stripped}")

            # Check for shell/escape sequences
            if any(char in cmd_stripped for char in [';', '|', '&', '\r']):
                errors.append(f"Line {i}: Invalid characters detected: {cmd_stripped}")

        # Check for unclosed config blocks
        if config_depth > 0:
            errors.append(f"Unclosed config block(s): {config_depth} 'end' statement(s) missing")

        return len(errors) == 0, errors

    @staticmethod
    def detect_config_section(commands: List[str]) -> Optional[str]:
        """
        Detect the primary config section from commands.

        Args:
            commands: List of FortiGate commands

        Returns:
            Config section name (e.g., "system global") or None

        Examples:
            >>> detect_config_section(["config system global", "set admin-https enable", "end"])
            'system global'
        """
        for cmd in commands:
            match = re.match(r'^config\s+(.+)$', cmd.strip(), re.IGNORECASE)
            if match:
                return match.group(1)
        return None


def apply_fortigate_defaults(
    parameters: Dict[str, str],
    defaults: Dict[str, str]
) -> Dict[str, str]:
    """
    Apply default values to FortiGate parameters.

    Args:
        parameters: User-provided parameters
        defaults: Default values

    Returns:
        Combined parameters with defaults applied

    Example:
        >>> apply_fortigate_defaults(
        ...     {"ADMIN_TIMEOUT": "15"},
        ...     {"ADMIN_TIMEOUT": "10", "SYSLOG_FACILITY": "local7"}
        ... )
        {'ADMIN_TIMEOUT': '15', 'SYSLOG_FACILITY': 'local7'}
    """
    result = defaults.copy()
    result.update(parameters)
    return result
