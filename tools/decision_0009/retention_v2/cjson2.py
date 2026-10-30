"""CJSON2 syntax codec for Decision 0009 Retention V2.

The codec implements only the encoding layer from r2 section 4.  Closed object
schemas, array bounds, semantic references, lifecycle, and authority remain the
responsibility of later consumers.
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import spec


_KEY_RE = re.compile(rf"\A(?:{spec.CJSON2_KEY_PATTERN})\Z", re.ASCII)


class CJSON2Error(ValueError):
    """Base class for deterministic CJSON2 codec failures."""

    stage = spec.ValidationStage.ENCODING


class CJSON2EncodeError(CJSON2Error):
    """The supplied Python value cannot be represented as CJSON2."""


class CJSON2DecodeError(CJSON2Error):
    """The supplied bytes are not canonical CJSON2."""


class _DecodeIssue(ValueError):
    pass


def _validate_scalar_string(value: str, error_type: type[CJSON2Error]) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise error_type("Unicode surrogate code points are not scalar values")


def _encode_string(value: str) -> str:
    _validate_scalar_string(value, CJSON2EncodeError)
    encoded: list[str] = ['"']
    for character in value:
        codepoint = ord(character)
        if character == '"':
            encoded.append('\\"')
        elif character == "\\":
            encoded.append("\\\\")
        elif codepoint <= 0x1F:
            encoded.append(f"\\u00{codepoint:02x}")
        else:
            encoded.append(character)
    encoded.append('"')
    return "".join(encoded)


def _encode(value: Any, depth: int) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, dict):
        if depth > spec.CJSON2_MAX_DEPTH:
            raise CJSON2EncodeError("maximum CJSON2 depth exceeded")
        if len(value) > spec.CJSON2_MAX_OBJECT_MEMBERS:
            raise CJSON2EncodeError("maximum CJSON2 object membership exceeded")
        for key in value:
            if not isinstance(key, str) or _KEY_RE.fullmatch(key) is None:
                raise CJSON2EncodeError("object key does not match the CJSON2 key grammar")
        parts = []
        for key in sorted(value, key=lambda item: item.encode("ascii")):
            parts.append(f"{_encode_string(key)}:{_encode(value[key], depth + 1)}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        if depth > spec.CJSON2_MAX_DEPTH:
            raise CJSON2EncodeError("maximum CJSON2 depth exceeded")
        return "[" + ",".join(_encode(item, depth + 1) for item in value) + "]"
    raise CJSON2EncodeError(f"unsupported CJSON2 value type: {type(value).__name__}")


def dumps(value: dict[str, Any]) -> bytes:
    """Serialize one root object to its canonical CJSON2 byte representation."""

    if not isinstance(value, dict):
        raise CJSON2EncodeError("the CJSON2 root must be an object")
    return _encode(value, 1).encode("utf-8")


def _reject_number(token: str) -> None:
    raise _DecodeIssue(f"JSON numeric token is forbidden: {token}")


def _reject_constant(token: str) -> None:
    raise _DecodeIssue(f"non-CJSON2 token is forbidden: {token}")


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > spec.CJSON2_MAX_OBJECT_MEMBERS:
        raise _DecodeIssue("maximum CJSON2 object membership exceeded")
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise _DecodeIssue("duplicate object key")
    if any(_KEY_RE.fullmatch(key) is None for key in keys):
        raise _DecodeIssue("object key does not match the CJSON2 key grammar")
    if keys != sorted(keys, key=lambda item: item.encode("ascii")):
        raise _DecodeIssue("object keys are not in unsigned ASCII order")
    return dict(pairs)


def _reject_over_depth(text: str) -> None:
    """Reject structural depth before a recursion-sensitive parser sees it."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
            if depth > spec.CJSON2_MAX_DEPTH:
                raise CJSON2DecodeError("maximum CJSON2 depth exceeded")
        elif character in "}]":
            depth -= 1


def _validate_decoded(value: Any, depth: int) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_scalar_string(value, CJSON2DecodeError)
        return
    if isinstance(value, dict):
        if depth > spec.CJSON2_MAX_DEPTH:
            raise CJSON2DecodeError("maximum CJSON2 depth exceeded")
        for nested in value.values():
            _validate_decoded(nested, depth + 1)
        return
    if isinstance(value, list):
        if depth > spec.CJSON2_MAX_DEPTH:
            raise CJSON2DecodeError("maximum CJSON2 depth exceeded")
        for nested in value:
            _validate_decoded(nested, depth + 1)
        return
    raise CJSON2DecodeError("decoded value has a forbidden CJSON2 type")


def loads(data: bytes) -> dict[str, Any]:
    """Parse canonical CJSON2 bytes and return the root object.

    This performs only encoding-layer validation.  Consumers must apply their
    exact closed schema before evaluating semantic references.
    """

    if not isinstance(data, bytes):
        raise CJSON2DecodeError("CJSON2 input must be exact bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CJSON2DecodeError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CJSON2DecodeError("CJSON2 input is not shortest-form valid UTF-8") from error
    _reject_over_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_int=_reject_number,
            parse_float=_reject_number,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, _DecodeIssue, RecursionError) as error:
        raise CJSON2DecodeError(str(error)) from error
    if not isinstance(value, dict):
        raise CJSON2DecodeError("the CJSON2 root must be an object")
    _validate_decoded(value, 1)
    try:
        canonical = dumps(value)
    except CJSON2EncodeError as error:
        raise CJSON2DecodeError(str(error)) from error
    if canonical != data:
        raise CJSON2DecodeError("input is not the canonical CJSON2 representation")
    return value
