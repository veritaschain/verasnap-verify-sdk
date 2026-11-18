"""Port of VeraSnap iOS `JSONCanonicalizer` (Sources/Utils/Utils.swift).

This is close to RFC 8785 (JCS) but not identical. The differences matter,
because the apps hash exactly these bytes:

* the numbers 0 and 1 (also 0.0 and 1.0) are written as ``false`` / ``true``
  (Swift bridges NSNumber 0/1 to Bool before the number branch);
* other integral numbers within the Int64 range are written as integers;
  non-integral numbers use Swift's ``Double.description`` (same text as
  Python's ``repr`` for finite doubles); NaN and infinities become ``null``;
* strings escape only ``"`` ``\\`` ``\\n`` ``\\r`` ``\\t`` and other characters
  below U+0020 as ``\\u00xx`` (lowercase hex); everything else is raw UTF-8,
  including U+007F, U+2028 and U+2029;
* a CR LF pair is one Swift ``Character`` whose first scalar is CR, so it is
  written as ``\\u000d`` and the LF is dropped;
* object keys are sorted by UTF-16 code units (NSString literal compare).
"""

from __future__ import annotations

import math
from typing import Any

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class CanonicalizationError(ValueError):
    pass


def _number(value: int | float) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value == 0 or value == 1:
        return "true" if value == 1 else "false"
    if isinstance(value, int):
        if _INT64_MIN <= value <= _INT64_MAX:
            return str(value)
        value = float(value)
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == int(value) and _INT64_MIN <= value < 2.0**63:
        return str(int(value))
    return repr(float(value))


def _string(text: str) -> str:
    out = ['"']
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\r" and i + 1 < n and text[i + 1] == "\n":
            out.append("\\u000d")
            i += 2
            continue
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
        i += 1
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def canonicalize_to_string(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_to_string(v) for v in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys(), key=_utf16_key):
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            parts.append(_string(key) + ":" + canonicalize_to_string(value[key]))
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(f"unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    return canonicalize_to_string(value).encode("utf-8")
