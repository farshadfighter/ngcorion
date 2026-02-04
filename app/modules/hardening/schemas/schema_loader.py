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
            check_numbers: List of CIS check numbers from audit results

        Returns:
            List of matching ControlDefinitions
        """
        schema = cls.get_schema(device_type)
        if not schema:
            return []

        check_map = cls.CHECK_TO_CONTROL_MAP.get(device_type, {})
        control_ids = set()

        for check_num in check_numbers:
            # Try direct match first
            if check_num in check_map:
                control_ids.add(check_map[check_num])
            else:
                # Try to find control by ID match
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
