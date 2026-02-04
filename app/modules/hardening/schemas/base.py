"""
Base Schema Models

Pydantic models for defining hardening control schemas.
Supports all input types: string, enum, bool, int, secret, text_multiline,
repeater, ordered_multi_enum, list_string, list_int, multi_enum, ref
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field


class InputType(str, Enum):
    """Supported input types for control fields."""
    STRING = "string"
    ENUM = "enum"
    BOOL = "bool"
    INT = "int"
    SECRET = "secret"
    TEXT_MULTILINE = "text_multiline"
    REPEATER = "repeater"
    ORDERED_MULTI_ENUM = "ordered_multi_enum"
    LIST_STRING = "list_string"
    LIST_INT = "list_int"
    MULTI_ENUM = "multi_enum"
    REF = "ref"


class DependsOn(BaseModel):
    """
    Conditional dependency definition.

    Supports three types of dependencies:
    1. field/equals - Show when field equals specific value
    2. any_in/values_include_any - Show when array field includes any of the values
    3. field/not_equals - Show when field does not equal value
    """
    field: Optional[str] = None
    equals: Optional[Any] = None
    not_equals: Optional[Any] = None
    any_in: Optional[List[str]] = None
    values_include_any: Optional[List[str]] = None


class ItemValidation(BaseModel):
    """Validation rules for list items."""
    type: Optional[str] = None  # "cidr_or_ip", "ip_or_fqdn", "ip_address"
    min: Optional[int] = None
    max: Optional[int] = None
    pattern: Optional[str] = None


class FieldDefinition(BaseModel):
    """Field definition for repeater item schema."""
    name: str
    type: InputType
    required: bool = False
    label: Optional[str] = None
    hint: Optional[str] = None
    default: Optional[Any] = None
    options: Optional[List[str]] = None
    min: Optional[int] = None
    max: Optional[int] = None
    depends_on: Optional[DependsOn] = None


class ItemSchema(BaseModel):
    """Schema for repeater items."""
    type: str = "object"
    fields: List[FieldDefinition]


class InputDefinition(BaseModel):
    """
    Complete input field definition.

    Supports all input types with their specific configurations.
    """
    name: str
    type: InputType
    required: bool = False
    label: Optional[str] = None
    hint: Optional[str] = None
    default: Optional[Any] = None

    # For enum/multi_enum/ordered_multi_enum
    options: Optional[List[str]] = None

    # For int type
    min: Optional[int] = None
    max: Optional[int] = None

    # For ref type
    ref: Optional[str] = None

    # For list_string/list_int
    item_validation: Optional[ItemValidation] = None

    # For repeater
    item_schema: Optional[ItemSchema] = None

    # Conditional visibility
    depends_on: Optional[DependsOn] = None

    class Config:
        use_enum_values = True


class ControlDefinition(BaseModel):
    """
    CIS Control definition.

    Represents a single hardening control with its inputs and metadata.
    """
    control_id: str
    title: str
    state_options: List[str] = Field(default=["SKIP", "AUDIT", "APPLY"])
    inputs: List[InputDefinition] = Field(default_factory=list)
    risk_level: Optional[str] = None  # "HIGH" for dangerous controls
    check_number: Optional[str] = None  # Related CIS check number

    class Config:
        use_enum_values = True


class SharedFieldDefinition(BaseModel):
    """
    Shared field that can be referenced across controls.

    Common fields like vty_lines, external_interface, etc.
    """
    type: InputType
    label: str
    required: bool = False
    hint: Optional[str] = None
    default: Optional[Any] = None
    options: Optional[List[str]] = None

    class Config:
        use_enum_values = True


class SchemaDefaults(BaseModel):
    """Default settings for the schema."""
    state: str = "AUDIT"
    show_preview_config: bool = True
    auto_fill_from_previous_inputs: bool = True


class ControlSchema(BaseModel):
    """
    Complete control schema for a device type.

    Contains all controls and shared fields for a specific device.
    """
    schema_version: str = "1.0"
    device_type: str
    profile: Optional[str] = None
    ui_mode: str = "control_by_control"
    defaults: SchemaDefaults = Field(default_factory=SchemaDefaults)
    shared_fields: Dict[str, SharedFieldDefinition] = Field(default_factory=dict)
    controls: List[ControlDefinition]

    class Config:
        use_enum_values = True

    def get_control(self, control_id: str) -> Optional[ControlDefinition]:
        """Get a control by its ID."""
        for control in self.controls:
            if control.control_id == control_id:
                return control
        return None

    def get_controls_by_ids(self, control_ids: List[str]) -> List[ControlDefinition]:
        """Get multiple controls by their IDs."""
        return [c for c in self.controls if c.control_id in control_ids]


# Type alias for control state values
ControlState = Dict[str, Any]  # {"state": "APPLY", "inputs": {...}}
