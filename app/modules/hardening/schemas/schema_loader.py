"""
Schema Loader

Loads and caches control schemas for different device types.
Provides access to controls and shared field resolution.
"""

import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from functools import lru_cache

from .base import (
    ControlSchema,
    ControlDefinition,
    InputDefinition,
    SharedFieldDefinition,
    InputType,
)


class SchemaLoader:
    """
    Loads and caches control schemas from JSON files.

    Supports:
    - Loading schemas per device type (cisco, fortinet, linux, windows, apache)
    - Caching for performance
    - Reference resolution for shared fields
    - Filtering controls by check numbers
    """

    # Mapping of device type to schema file path
    SCHEMA_PATHS = {
        "cisco": "cisco/controls.json",
        "fortinet": "fortinet/controls.json",
        "linux": "linux/controls.json",
        "windows": "windows/controls.json",
        "apache": "apache/controls.json",
    }

    # Control ID to check number mapping (for post-audit mode)
    # This maps CIS check numbers to control IDs
    CHECK_TO_CONTROL_MAP: Dict[str, Dict[str, str]] = {}

    # Static audit check number to control ID mapping
    # Maps audit rule IDs (IOS-L1-xxx) to schema control IDs
    AUDIT_CHECK_TO_CONTROL: Dict[str, Dict[str, str]] = {
        "cisco": {
            # Authentication & Authorization
            "IOS-L1-020": "1.1.1",      # AAA new-model enabled
            "IOS-L1-021": "1.1.2",      # AAA authentication for login defined
            "IOS-L1-022": "1.1.6",      # AAA accounting commands 15 configured

            # SSH & VTY Access
            "IOS-L1-010": "1.2.2",      # Telnet disabled; SSH only on VTY
            "IOS-L1-011": "2.1.1.4",    # SSH version 2 enforced -> ip ssh timeout
            "IOS-L1-007": "2.1.1.4",    # SSH version 2 -> ip ssh timeout (closest match)
            "IOS-L1-003": "1.2.5",      # VTY restricted by access-class
            "IOS-L1-004": "1.1.4",      # Explicit login method on VTY
            "IOS-L1-0112": "1.2.6",     # SSH timeout configured
            "IOS-L1-0113": "1.2.7",     # SSH auth-retries configured
            "IOS-L1-0120": "1.2.8",     # SSH/RSA key size >= 2048

            # Passwords & Secrets
            "IOS-L1-001": "1.4.1",      # Use 'enable secret' only
            "IOS-L1-002": "1.3.1",      # Console & VTY exec-timeout

            # Banners
            "IOS-L1-005": "1.4.2",      # MOTD banner configured
            "IOS-L1-0051": "1.4.3",     # Login banner configured

            # Logging
            "IOS-L1-024": "2.2.1",      # Remote syslog configured
            "IOS-L1-0241": "2.2.2",     # Log timestamps configured
            "IOS-L1-0242": "2.2.3",     # Logging buffered size configured
            "IOS-L1-0243": "2.2.4",     # Logging trap level configured
            "IOS-L1-0244": "2.2.5",     # Archive config logging enabled

            # System Hardening
            "IOS-L1-0010": "1.5.1",     # Hostname configured
            "IOS-L1-0011": "1.5.2",     # IP domain-name configured
            "IOS-L1-0012": "1.5.3",     # DNS lookup disabled in exec mode
            "IOS-L1-0130": "1.3.3",     # Login block-for configured
            "IOS-L1-0131": "1.3.4",     # Login on-failure/on-success logging

            # Services & Protocols
            # "IOS-L1-018": No matching control - CDP disable not in schema
            # "IOS-L1-061": No matching control - Interface ACL not in schema

            # SNMP
            "IOS-L1-030A": "2.3.1",     # SNMPv3 configured
            "IOS-L1-030B": "2.3.2",     # SNMP community with ACL

            # Network Hardening
            "IOS-INFO-043": "3.1.1",    # Directed broadcast disabled
            "IOS-INFO-050": "3.1.2",    # Source routing disabled
        }
    }

    _schemas: Dict[str, ControlSchema] = {}
    _base_path: Path = Path(__file__).parent

    @classmethod
    def get_schema(cls, device_type: str) -> Optional[ControlSchema]:
        """
        Load and cache the schema for a device type.

        Args:
            device_type: One of 'cisco', 'fortinet', 'linux', 'windows', 'apache'

        Returns:
            ControlSchema or None if not found
        """
        device_type = device_type.lower()

        # Return cached if available
        if device_type in cls._schemas:
            return cls._schemas[device_type]

        # Load from file
        schema_path = cls.SCHEMA_PATHS.get(device_type)
        if not schema_path:
            return None

        full_path = cls._base_path / schema_path
        if not full_path.exists():
            return None

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            schema = ControlSchema(**data)
            cls._schemas[device_type] = schema

            # Build check-to-control mapping
            cls._build_check_mapping(device_type, schema)

            return schema
        except Exception as e:
            print(f"Error loading schema for {device_type}: {e}")
            return None

    @classmethod
    def _build_check_mapping(cls, device_type: str, schema: ControlSchema):
        """Build mapping from check numbers to control IDs."""
        if device_type not in cls.CHECK_TO_CONTROL_MAP:
            cls.CHECK_TO_CONTROL_MAP[device_type] = {}

        for control in schema.controls:
            # Use control_id as check_number if not specified
            check_num = control.check_number or control.control_id
            cls.CHECK_TO_CONTROL_MAP[device_type][check_num] = control.control_id

    @classmethod
    def get_control(cls, device_type: str, control_id: str) -> Optional[ControlDefinition]:
        """
        Get a specific control by ID.

        Args:
            device_type: Device type
            control_id: Control ID (e.g., "1.1.1")

        Returns:
            ControlDefinition or None
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return None
        return schema.get_control(control_id)

    @classmethod
    def get_controls_for_checks(
        cls,
        device_type: str,
        check_numbers: List[str]
    ) -> List[ControlDefinition]:
        """
        Get controls for specific check numbers (post-audit mode).

        Maps audit check numbers to control IDs and returns matching controls.

        Args:
            device_type: Device type
            check_numbers: List of CIS check numbers from audit results (e.g., IOS-L1-001)

        Returns:
            List of matching ControlDefinitions
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return []

        # Get static audit check mapping
        audit_check_map = cls.AUDIT_CHECK_TO_CONTROL.get(device_type, {})
        # Get dynamic mapping from schema (check_number fields)
        schema_check_map = cls.CHECK_TO_CONTROL_MAP.get(device_type, {})

        control_ids = set()

        for check_num in check_numbers:
            # Try static audit check mapping first (IOS-L1-xxx -> 1.x.x)
            if check_num in audit_check_map:
                control_ids.add(audit_check_map[check_num])
            # Try schema-defined check_number mapping
            elif check_num in schema_check_map:
                control_ids.add(schema_check_map[check_num])
            else:
                # Try to find control by ID match (if check_num is already a control_id)
                for control in schema.controls:
                    if control.control_id == check_num:
                        control_ids.add(control.control_id)
                        break

        return schema.get_controls_by_ids(list(control_ids))

    @classmethod
    def get_all_controls(cls, device_type: str) -> List[ControlDefinition]:
        """
        Get all controls for a device type (full hardening mode).

        Args:
            device_type: Device type

        Returns:
            List of all ControlDefinitions
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return []
        return schema.controls

    @classmethod
    def resolve_ref(
        cls,
        device_type: str,
        ref: str
    ) -> Optional[SharedFieldDefinition]:
        """
        Resolve a reference to a shared field.

        Args:
            device_type: Device type
            ref: Reference string (e.g., "shared_fields.vty_lines")

        Returns:
            SharedFieldDefinition or None
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return None

        # Parse reference (format: "shared_fields.field_name")
        parts = ref.split(".")
        if len(parts) != 2 or parts[0] != "shared_fields":
            return None

        field_name = parts[1]
        return schema.shared_fields.get(field_name)

    @classmethod
    def get_shared_fields(cls, device_type: str) -> Dict[str, SharedFieldDefinition]:
        """
        Get all shared fields for a device type.

        Args:
            device_type: Device type

        Returns:
            Dictionary of shared field definitions
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return {}
        return schema.shared_fields

    @classmethod
    def get_input_as_shared_field(
        cls,
        input_def: InputDefinition,
        device_type: str
    ) -> Optional[InputDefinition]:
        """
        If input is a ref type, resolve it to an actual input definition.

        Args:
            input_def: Input definition (possibly a ref)
            device_type: Device type for resolution

        Returns:
            Resolved InputDefinition or original if not a ref
        """
        if input_def.type != InputType.REF or not input_def.ref:
            return input_def

        shared_field = cls.resolve_ref(device_type, input_def.ref)
        if not shared_field:
            return input_def

        # Create resolved input definition
        return InputDefinition(
            name=input_def.name,
            type=shared_field.type,
            required=input_def.required,
            label=shared_field.label,
            hint=shared_field.hint,
            default=shared_field.default,
            options=shared_field.options,
            depends_on=input_def.depends_on,
        )

    @classmethod
    def clear_cache(cls):
        """Clear the schema cache."""
        cls._schemas.clear()
        cls.CHECK_TO_CONTROL_MAP.clear()

    @classmethod
    def reload_schema(cls, device_type: str) -> Optional[ControlSchema]:
        """
        Force reload a schema from disk.

        Args:
            device_type: Device type to reload

        Returns:
            Reloaded ControlSchema or None
        """
        device_type = device_type.lower()
        if device_type in cls._schemas:
            del cls._schemas[device_type]
        if device_type in cls.CHECK_TO_CONTROL_MAP:
            del cls.CHECK_TO_CONTROL_MAP[device_type]
        return cls.get_schema(device_type)
