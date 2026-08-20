"""Small dependency-free validator for the JSON Schema subset used by model calls."""

from __future__ import annotations

import re
from typing import Any


class JsonSchemaViolation(ValueError):
    """Raised when structured model data does not satisfy its requested schema."""


def validate_json_schema(data: Any, schema: dict[str, Any]) -> None:
    """Validate common draft-2020-12 constraints without adding a new dependency."""

    _validate(data, schema, schema, path="$")


def _validate(data: Any, schema: dict[str, Any], root: dict[str, Any], *, path: str) -> None:
    if "$ref" in schema:
        target = _resolve_ref(root, schema["$ref"])
        _validate(data, target, root, path=path)
        return

    if "allOf" in schema:
        for child in schema["allOf"]:
            _validate(data, child, root, path=path)

    if "anyOf" in schema:
        if not _matches_any(data, schema["anyOf"], root, path):
            raise JsonSchemaViolation(f"{path} does not match any allowed schema")
        return

    if "oneOf" in schema:
        matches = sum(_matches(data, child, root, path) for child in schema["oneOf"])
        if matches != 1:
            raise JsonSchemaViolation(f"{path} must match exactly one allowed schema")
        return

    if "const" in schema and data != schema["const"]:
        raise JsonSchemaViolation(f"{path} does not equal the required constant")
    if "enum" in schema and data not in schema["enum"]:
        raise JsonSchemaViolation(f"{path} is not an allowed value")

    expected = schema.get("type")
    if isinstance(expected, list):
        if not any(_is_type(data, item) for item in expected):
            raise JsonSchemaViolation(f"{path} has an invalid type")
    elif isinstance(expected, str) and not _is_type(data, expected):
        raise JsonSchemaViolation(f"{path} must be {expected}")

    if isinstance(data, dict):
        _validate_object(data, schema, root, path)
    elif isinstance(data, list):
        _validate_array(data, schema, root, path)
    elif isinstance(data, str):
        _validate_string(data, schema, path)
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        _validate_number(data, schema, path)


def _resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise JsonSchemaViolation("only local JSON Schema references are supported")
    current: Any = root
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            raise JsonSchemaViolation(f"unresolved JSON Schema reference: {reference}")
        current = current[key]
    if not isinstance(current, dict):
        raise JsonSchemaViolation(f"JSON Schema reference is not an object: {reference}")
    return current


def _matches(data: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> bool:
    try:
        _validate(data, schema, root, path=path)
    except JsonSchemaViolation:
        return False
    return True


def _matches_any(
    data: Any, schemas: list[dict[str, Any]], root: dict[str, Any], path: str
) -> bool:
    return any(_matches(data, child, root, path) for child in schemas)


def _is_type(data: Any, expected: str) -> bool:
    return {
        "null": data is None,
        "object": isinstance(data, dict),
        "array": isinstance(data, list),
        "string": isinstance(data, str),
        "integer": isinstance(data, int) and not isinstance(data, bool),
        "number": isinstance(data, (int, float)) and not isinstance(data, bool),
        "boolean": isinstance(data, bool),
    }.get(expected, True)


def _validate_object(
    data: dict[str, Any], schema: dict[str, Any], root: dict[str, Any], path: str
) -> None:
    required = schema.get("required", [])
    missing = [name for name in required if name not in data]
    if missing:
        raise JsonSchemaViolation(f"{path} is missing required fields: {', '.join(missing)}")

    properties = schema.get("properties", {})
    for name, value in data.items():
        if name in properties:
            _validate(value, properties[name], root, path=f"{path}.{name}")
            continue
        additional = schema.get("additionalProperties", True)
        if additional is False:
            raise JsonSchemaViolation(f"{path}.{name} is not allowed")
        if isinstance(additional, dict):
            _validate(value, additional, root, path=f"{path}.{name}")


def _validate_array(
    data: list[Any], schema: dict[str, Any], root: dict[str, Any], path: str
) -> None:
    if len(data) < schema.get("minItems", 0):
        raise JsonSchemaViolation(f"{path} contains too few items")
    if "maxItems" in schema and len(data) > schema["maxItems"]:
        raise JsonSchemaViolation(f"{path} contains too many items")
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for index, value in enumerate(data):
            _validate(value, item_schema, root, path=f"{path}[{index}]")


def _validate_string(data: str, schema: dict[str, Any], path: str) -> None:
    if len(data) < schema.get("minLength", 0):
        raise JsonSchemaViolation(f"{path} is shorter than allowed")
    if "maxLength" in schema and len(data) > schema["maxLength"]:
        raise JsonSchemaViolation(f"{path} is longer than allowed")
    if "pattern" in schema and re.search(schema["pattern"], data) is None:
        raise JsonSchemaViolation(f"{path} does not match the required pattern")


def _validate_number(data: int | float, schema: dict[str, Any], path: str) -> None:
    if "minimum" in schema and data < schema["minimum"]:
        raise JsonSchemaViolation(f"{path} is below the minimum")
    if "maximum" in schema and data > schema["maximum"]:
        raise JsonSchemaViolation(f"{path} is above the maximum")
