"""Small, dependency-free validator for plugin JSON-schema boundaries.

The public contract carries JSON Schema as data.  Plugins only need the strict
subset implemented here; unsupported schema keywords fail closed instead of
silently weakening validation.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from typing import Any


class ArgumentValidationError(ValueError):
    """Raised when structured plugin arguments do not match their schema."""


_SUPPORTED_KEYWORDS = {
    "$schema",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "pattern",
}


def validate_arguments(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and deep-copy a JSON-like argument object."""

    if not isinstance(arguments, Mapping):
        raise ArgumentValidationError("arguments must be an object")
    _validate_schema_shape(schema, path="$schema")
    value = copy.deepcopy(dict(arguments))
    _validate_value(value, schema, path="$")
    return value


def _validate_schema_shape(schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(schema, Mapping):
        raise ArgumentValidationError(f"{path}: schema must be an object")
    unsupported = set(schema) - _SUPPORTED_KEYWORDS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ArgumentValidationError(f"{path}: unsupported schema keyword(s): {names}")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        raise ArgumentValidationError(f"{path}.properties must be an object")
    for name, child in properties.items():
        _validate_schema_shape(child, path=f"{path}.properties.{name}")
    additional = schema.get("additionalProperties")
    if isinstance(additional, Mapping):
        _validate_schema_shape(additional, path=f"{path}.additionalProperties")
    if "items" in schema:
        _validate_schema_shape(schema["items"], path=f"{path}.items")


def _validate_value(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if "enum" in schema and value not in schema["enum"]:
        raise ArgumentValidationError(f"{path}: value is not in the allowed enum")
    if "const" in schema and value != schema["const"]:
        raise ArgumentValidationError(f"{path}: value does not match the required constant")

    expected_type = schema.get("type")
    if expected_type == "object":
        _validate_object(value, schema, path=path)
    elif expected_type == "array":
        _validate_array(value, schema, path=path)
    elif expected_type == "string":
        _validate_string(value, schema, path=path)
    elif expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ArgumentValidationError(f"{path}: expected integer")
        _validate_number(value, schema, path=path)
    elif expected_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ArgumentValidationError(f"{path}: expected number")
        _validate_number(value, schema, path=path)
    elif expected_type == "boolean":
        if not isinstance(value, bool):
            raise ArgumentValidationError(f"{path}: expected boolean")
    elif expected_type == "null":
        if value is not None:
            raise ArgumentValidationError(f"{path}: expected null")
    elif expected_type is not None:
        raise ArgumentValidationError(f"{path}: unsupported type {expected_type!r}")


def _validate_object(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(value, dict):
        raise ArgumentValidationError(f"{path}: expected object")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(required, Sequence) or isinstance(required, (str, bytes)):
        raise ArgumentValidationError(f"{path}: schema required must be an array")
    missing = [name for name in required if name not in value]
    if missing:
        raise ArgumentValidationError(f"{path}: missing required field(s): {', '.join(missing)}")

    extras = set(value) - set(properties)
    additional = schema.get("additionalProperties", True)
    if extras and additional is False:
        raise ArgumentValidationError(f"{path}: unknown field(s): {', '.join(sorted(extras))}")
    if extras and isinstance(additional, Mapping):
        for name in extras:
            _validate_value(value[name], additional, path=f"{path}.{name}")
    for name, child_schema in properties.items():
        if name in value:
            _validate_value(value[name], child_schema, path=f"{path}.{name}")


def _validate_array(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(value, list):
        raise ArgumentValidationError(f"{path}: expected array")
    minimum = schema.get("minItems")
    maximum = schema.get("maxItems")
    if minimum is not None and len(value) < minimum:
        raise ArgumentValidationError(f"{path}: too few items")
    if maximum is not None and len(value) > maximum:
        raise ArgumentValidationError(f"{path}: too many items")
    item_schema = schema.get("items")
    if item_schema is not None:
        for index, item in enumerate(value):
            _validate_value(item, item_schema, path=f"{path}[{index}]")


def _validate_string(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(value, str):
        raise ArgumentValidationError(f"{path}: expected string")
    minimum = schema.get("minLength")
    maximum = schema.get("maxLength")
    if minimum is not None and len(value) < minimum:
        raise ArgumentValidationError(f"{path}: string is too short")
    if maximum is not None and len(value) > maximum:
        raise ArgumentValidationError(f"{path}: string is too long")
    pattern = schema.get("pattern")
    if pattern is not None and re.search(pattern, value) is None:
        raise ArgumentValidationError(f"{path}: string does not match the required pattern")


def _validate_number(value: int | float, schema: Mapping[str, Any], *, path: str) -> None:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if minimum is not None and value < minimum:
        raise ArgumentValidationError(f"{path}: value is below the minimum")
    if maximum is not None and value > maximum:
        raise ArgumentValidationError(f"{path}: value exceeds the maximum")
