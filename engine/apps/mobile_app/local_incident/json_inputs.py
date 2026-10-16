"""[code] Bounded JSON copying shared by the two pure request entry points.

[code] Limits are provisional local safety policy, not recovered server limits.
"""

import json
import math

MAX_BODY_BYTES = 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 10_000
MAX_STRING_BYTES = 256 * 1024
MAX_LIST_ITEMS = 1000


class ContractError(ValueError):
    """A safe field-oriented validation error; never contains request values."""


def field_path(parent, key, known_fields=()):
    # [code] Only a caller-supplied static schema grants a name error-label authority.
    safe = key if key in known_fields else "<key>"
    return f"{parent}.{safe}" if parent else safe


def fail(path, reason):
    raise ContractError(f"{path or 'body'}: {reason}") from None


def _string_size(value, path):
    if len(value) > MAX_STRING_BYTES:
        fail(path, "string exceeds byte limit")
    try:
        length = len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        fail(path, "must contain valid UTF-8 text")
    if length > MAX_STRING_BYTES:
        fail(path, "string exceeds byte limit")
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


class _Budget:
    def __init__(self):
        self.nodes = 0
        self.bytes = 0

    def visit(self, path, depth):
        # [code] This fresh accounting object is intentionally mutable, never input.
        self.nodes += 1
        if depth > MAX_DEPTH:
            fail(path, "JSON nesting exceeds limit")
        if self.nodes > MAX_NODES:
            fail(path, "JSON node count exceeds limit")

    def add_bytes(self, amount, path):
        self.bytes += amount
        if self.bytes > MAX_BODY_BYTES:
            fail(path, "JSON representation exceeds byte limit")


def _copy_object(value, path, depth, budget, field_labels):
    budget.add_bytes(2 + max(0, len(value) - 1), path)
    result = {}
    labels = field_labels or {}
    for key, item in value.items():
        if type(key) is not str:
            fail(path, "JSON object keys must be strings")
        child_path = field_path(path, key, labels)
        budget.add_bytes(_string_size(key, child_path) + 1, child_path)
        result[key] = _copy_value(item, child_path, depth + 1, budget, labels.get(key))
    return result


def _copy_array(value, path, depth, budget, field_labels):
    if len(value) > MAX_LIST_ITEMS:
        fail(path, "array exceeds item limit")
    budget.add_bytes(2 + max(0, len(value) - 1), path)
    return [_copy_value(item, f"{path}[{index}]", depth + 1, budget, field_labels)
            for index, item in enumerate(value)]


def _copy_value(value, path, depth, budget, field_labels):
    budget.visit(path, depth)
    kind = type(value)
    if kind is dict:
        return _copy_object(value, path, depth, budget, field_labels)
    if kind is list:
        return _copy_array(value, path, depth, budget, field_labels)
    if kind is str:
        budget.add_bytes(_string_size(value, path), path)
        return value
    if value is None or kind is bool:
        budget.add_bytes(len(json.dumps(value)), path)
        return value
    if kind is int or kind is float:
        if kind is float and not math.isfinite(value):
            fail(path, "number must be finite")
        try:
            size = len(json.dumps(value, allow_nan=False))
        except (ValueError, OverflowError):
            fail(path, "number exceeds representation bounds")
        budget.add_bytes(size, path)
        return value
    fail(path, "must be a JSON value")


def copy_json_object(value, field_labels=None):
    if type(value) is not dict:
        fail("body", "must be a JSON object")
    return _copy_value(value, "", 1, _Budget(), field_labels)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(field_path("", key), "duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    fail("body", "number must be finite")


def decode_body(raw):
    if type(raw) is not bytes:
        fail("body", "must be UTF-8 JSON bytes")
    if len(raw) > MAX_BODY_BYTES:
        fail("body", "request exceeds byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except ContractError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        # [code] Decoder exceptions can embed source text; never expose their messages.
        fail("body", "must be a valid UTF-8 JSON object within nesting bounds")
    return copy_json_object(parsed)
