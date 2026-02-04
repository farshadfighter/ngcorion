"""
Schema Validator

Validates user inputs against control schemas.
Handles dependency checking, type validation, and nested field validation.
"""

import re
import ipaddress
from typing import Dict, Any, List, Tuple, Optional, Set

from .base import (
    InputDefinition,
    ControlDefinition,
    DependsOn,
    ItemValidation,
    InputType,
    ControlSchema,
)
from .schema_loader import SchemaLoader


class ValidationError:
    """Represents a validation error for a field."""

    def __init__(self, field: str, message: str, control_id: Optional[str] = None):
        self.field = field
        self.message = message
        self.control_id = control_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "message": self.message,
            "control_id": self.control_id,
        }


class SchemaValidator:
    """
    Validates control inputs against schema definitions.

    Supports:
    - Type-specific validation (string, int, bool, enum, etc.)
    - Dependency checking for conditional fields
    - Nested repeater validation
    - List item validation (IP, CIDR, etc.)
    """

    # IP address regex pattern
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    # CIDR notation pattern
    CIDR_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r'(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?$'
    )

    # FQDN pattern
    FQDN_PATTERN = re.compile(
        r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
        r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
    )

    @classmethod
    def validate_control_inputs(
        cls,
        control: ControlDefinition,
        values: Dict[str, Any],
        shared_fields: Dict[str, Any],
        device_type: str
    ) -> Tuple[bool, List[ValidationError]]:
        """
        Validate all inputs for a control.

        Args:
            control: Control definition
            values: User-provided values for the control
            shared_fields: Values for shared fields
            device_type: Device type for ref resolution

        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors: List[ValidationError] = []

        for input_def in control.inputs:
            # Resolve ref types
            resolved_input = SchemaLoader.get_input_as_shared_field(input_def, device_type)
            if not resolved_input:
                continue

            # Check dependency
            if not cls._check_dependency(input_def.depends_on, values, shared_fields):
                # Field is not visible, skip validation
                continue

            # Get value (from control values or shared fields for ref types)
            if input_def.type == InputType.REF:
                value = shared_fields.get(input_def.name)
            else:
                value = values.get(input_def.name)

            # Validate the field
            field_errors = cls._validate_field(
                resolved_input,
                value,
                control.control_id,
                values,
                shared_fields,
                device_type
            )
            errors.extend(field_errors)

        return len(errors) == 0, errors

    @classmethod
    def validate_all_controls(
        cls,
        device_type: str,
        control_states: Dict[str, Dict[str, Any]],
        shared_field_values: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, List[ValidationError]]]:
        """
        Validate inputs for all controls with APPLY state.

        Args:
            device_type: Device type
            control_states: Dict of {control_id: {"state": str, "inputs": dict}}
            shared_field_values: Values for shared fields

        Returns:
            Tuple of (all_valid, dict of {control_id: errors})
        """
        schema = SchemaLoader.get_schema(device_type)
        if not schema:
            return False, {"_schema": [ValidationError("_schema", f"Unknown device type: {device_type}")]}

        all_errors: Dict[str, List[ValidationError]] = {}
        all_valid = True

        for control_id, state_data in control_states.items():
            state = state_data.get("state", "SKIP")

            # Only validate APPLY controls
            if state != "APPLY":
                continue

            control = schema.get_control(control_id)
            if not control:
                all_errors[control_id] = [
                    ValidationError("_control", f"Unknown control: {control_id}", control_id)
                ]
                all_valid = False
                continue

            inputs = state_data.get("inputs", {})
            valid, errors = cls.validate_control_inputs(
                control, inputs, shared_field_values, device_type
            )

            if not valid:
                all_errors[control_id] = errors
                all_valid = False

        return all_valid, all_errors

    @classmethod
    def _check_dependency(
        cls,
        depends_on: Optional[DependsOn],
        values: Dict[str, Any],
        shared_fields: Dict[str, Any]
    ) -> bool:
        """
        Check if a field's dependency is met.

        Args:
            depends_on: Dependency definition
            values: Control input values
            shared_fields: Shared field values

        Returns:
            True if dependency is met (field should be visible)
        """
        if not depends_on:
            return True

        # Get the referenced value
        if depends_on.field:
            # Simple field dependency
            field_value = values.get(depends_on.field, shared_fields.get(depends_on.field))

            if depends_on.equals is not None:
                return field_value == depends_on.equals

            if depends_on.not_equals is not None:
                return field_value != depends_on.not_equals

        if depends_on.any_in and depends_on.values_include_any:
            # Array includes any check
            for field_name in depends_on.any_in:
                field_value = values.get(field_name, shared_fields.get(field_name))
                if isinstance(field_value, list):
                    for check_val in depends_on.values_include_any:
                        if check_val in field_value:
                            return True
            return False

        return True

    @classmethod
    def _validate_field(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str,
        all_values: Dict[str, Any],
        shared_fields: Dict[str, Any],
        device_type: str
    ) -> List[ValidationError]:
        """
        Validate a single field based on its type.

        Args:
            input_def: Input definition
            value: Field value
            control_id: Parent control ID
            all_values: All values in the control
            shared_fields: Shared field values
            device_type: Device type

        Returns:
            List of validation errors
        """
        errors: List[ValidationError] = []
        field_name = input_def.name

        # Required check
        if input_def.required:
            if value is None or value == "" or value == []:
                errors.append(ValidationError(
                    field_name,
                    f"{input_def.label or field_name} is required",
                    control_id
                ))
                return errors

        # Skip further validation if empty and not required
        if value is None or value == "":
            return errors

        # Type-specific validation
        input_type = input_def.type
        if isinstance(input_type, str):
            input_type = InputType(input_type)

        if input_type == InputType.STRING:
            errors.extend(cls._validate_string(input_def, value, control_id))

        elif input_type == InputType.INT:
            errors.extend(cls._validate_int(input_def, value, control_id))

        elif input_type == InputType.BOOL:
            errors.extend(cls._validate_bool(input_def, value, control_id))

        elif input_type == InputType.ENUM:
            errors.extend(cls._validate_enum(input_def, value, control_id))

        elif input_type == InputType.MULTI_ENUM:
            errors.extend(cls._validate_multi_enum(input_def, value, control_id))

        elif input_type == InputType.ORDERED_MULTI_ENUM:
            errors.extend(cls._validate_ordered_multi_enum(input_def, value, control_id))

        elif input_type == InputType.SECRET:
            errors.extend(cls._validate_secret(input_def, value, control_id))

        elif input_type == InputType.TEXT_MULTILINE:
            errors.extend(cls._validate_text_multiline(input_def, value, control_id))

        elif input_type == InputType.LIST_STRING:
            errors.extend(cls._validate_list_string(input_def, value, control_id))

        elif input_type == InputType.LIST_INT:
            errors.extend(cls._validate_list_int(input_def, value, control_id))

        elif input_type == InputType.REPEATER:
            errors.extend(cls._validate_repeater(
                input_def, value, control_id, device_type
            ))

        return errors

    @classmethod
    def _validate_string(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate string input."""
        errors = []
        if not isinstance(value, str):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a string",
                control_id
            ))
        return errors

    @classmethod
    def _validate_int(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate integer input with min/max."""
        errors = []
        try:
            int_value = int(value)
            if input_def.min is not None and int_value < input_def.min:
                errors.append(ValidationError(
                    input_def.name,
                    f"{input_def.label or input_def.name} must be at least {input_def.min}",
                    control_id
                ))
            if input_def.max is not None and int_value > input_def.max:
                errors.append(ValidationError(
                    input_def.name,
                    f"{input_def.label or input_def.name} must be at most {input_def.max}",
                    control_id
                ))
        except (ValueError, TypeError):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a valid integer",
                control_id
            ))
        return errors

    @classmethod
    def _validate_bool(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate boolean input."""
        errors = []
        if not isinstance(value, bool):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be true or false",
                control_id
            ))
        return errors

    @classmethod
    def _validate_enum(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate enum (single select) input."""
        errors = []
        if input_def.options and value not in input_def.options:
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be one of: {', '.join(input_def.options)}",
                control_id
            ))
        return errors

    @classmethod
    def _validate_multi_enum(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate multi-enum (multi select) input."""
        errors = []
        if not isinstance(value, list):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a list",
                control_id
            ))
            return errors

        if input_def.options:
            invalid = [v for v in value if v not in input_def.options]
            if invalid:
                errors.append(ValidationError(
                    input_def.name,
                    f"Invalid values for {input_def.label or input_def.name}: {', '.join(invalid)}",
                    control_id
                ))
        return errors

    @classmethod
    def _validate_ordered_multi_enum(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate ordered multi-enum input (order matters)."""
        # Same validation as multi_enum, order is preserved by list
        return cls._validate_multi_enum(input_def, value, control_id)

    @classmethod
    def _validate_secret(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate secret/password input."""
        errors = []
        if not isinstance(value, str):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a string",
                control_id
            ))
        return errors

    @classmethod
    def _validate_text_multiline(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate multiline text input."""
        errors = []
        if not isinstance(value, str):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a string",
                control_id
            ))
        return errors

    @classmethod
    def _validate_list_string(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate list of strings with optional item validation."""
        errors = []
        if not isinstance(value, list):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a list",
                control_id
            ))
            return errors

        # Validate each item
        for i, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(ValidationError(
                    f"{input_def.name}[{i}]",
                    f"Item {i + 1} must be a string",
                    control_id
                ))
                continue

            # Item-specific validation
            if input_def.item_validation:
                item_errors = cls._validate_item(
                    input_def.item_validation, item, input_def.name, i, control_id
                )
                errors.extend(item_errors)

        return errors

    @classmethod
    def _validate_list_int(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str
    ) -> List[ValidationError]:
        """Validate list of integers with optional min/max."""
        errors = []
        if not isinstance(value, list):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a list",
                control_id
            ))
            return errors

        for i, item in enumerate(value):
            try:
                int_val = int(item)
                if input_def.item_validation:
                    if input_def.item_validation.min is not None and int_val < input_def.item_validation.min:
                        errors.append(ValidationError(
                            f"{input_def.name}[{i}]",
                            f"Item {i + 1} must be at least {input_def.item_validation.min}",
                            control_id
                        ))
                    if input_def.item_validation.max is not None and int_val > input_def.item_validation.max:
                        errors.append(ValidationError(
                            f"{input_def.name}[{i}]",
                            f"Item {i + 1} must be at most {input_def.item_validation.max}",
                            control_id
                        ))
            except (ValueError, TypeError):
                errors.append(ValidationError(
                    f"{input_def.name}[{i}]",
                    f"Item {i + 1} must be a valid integer",
                    control_id
                ))

        return errors

    @classmethod
    def _validate_item(
        cls,
        validation: ItemValidation,
        value: str,
        field_name: str,
        index: int,
        control_id: str
    ) -> List[ValidationError]:
        """Validate a list item based on its validation rules."""
        errors = []

        if validation.type == "ip_address":
            if not cls.IP_PATTERN.match(value):
                errors.append(ValidationError(
                    f"{field_name}[{index}]",
                    f"Item {index + 1} must be a valid IP address",
                    control_id
                ))

        elif validation.type == "cidr_or_ip":
            if not cls.CIDR_PATTERN.match(value):
                errors.append(ValidationError(
                    f"{field_name}[{index}]",
                    f"Item {index + 1} must be a valid IP address or CIDR notation",
                    control_id
                ))

        elif validation.type == "ip_or_fqdn":
            is_ip = cls.IP_PATTERN.match(value)
            is_fqdn = cls.FQDN_PATTERN.match(value)
            if not (is_ip or is_fqdn):
                errors.append(ValidationError(
                    f"{field_name}[{index}]",
                    f"Item {index + 1} must be a valid IP address or hostname",
                    control_id
                ))

        return errors

    @classmethod
    def _validate_repeater(
        cls,
        input_def: InputDefinition,
        value: Any,
        control_id: str,
        device_type: str
    ) -> List[ValidationError]:
        """Validate repeater (array of objects) input."""
        errors = []

        if not isinstance(value, list):
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} must be a list",
                control_id
            ))
            return errors

        if input_def.required and len(value) == 0:
            errors.append(ValidationError(
                input_def.name,
                f"{input_def.label or input_def.name} requires at least one entry",
                control_id
            ))
            return errors

        if not input_def.item_schema or not input_def.item_schema.fields:
            return errors

        # Validate each item
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                errors.append(ValidationError(
                    f"{input_def.name}[{i}]",
                    f"Item {i + 1} must be an object",
                    control_id
                ))
                continue

            # Validate each field in the item
            for field_def in input_def.item_schema.fields:
                # Check dependency within item
                if not cls._check_dependency(field_def.depends_on, item, {}):
                    continue

                field_value = item.get(field_def.name)

                # Required check
                if field_def.required and (field_value is None or field_value == ""):
                    errors.append(ValidationError(
                        f"{input_def.name}[{i}].{field_def.name}",
                        f"{field_def.label or field_def.name} is required in item {i + 1}",
                        control_id
                    ))
                    continue

                if field_value is None or field_value == "":
                    continue

                # Type validation for nested field
                nested_input = InputDefinition(
                    name=f"{input_def.name}[{i}].{field_def.name}",
                    type=field_def.type,
                    required=field_def.required,
                    label=field_def.label,
                    options=field_def.options,
                    min=field_def.min,
                    max=field_def.max,
                )

                field_errors = cls._validate_field(
                    nested_input, field_value, control_id, item, {}, device_type
                )
                errors.extend(field_errors)

        return errors
