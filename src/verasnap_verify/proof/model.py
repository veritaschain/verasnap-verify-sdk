"""Legacy projection of an internal proof.json event onto the iOS 1.6 model.

The iOS verifier decodes the event into `CPPEventJSON` and re-encodes it
before hashing, so keys it does not know are dropped and null optionals are
omitted. `project` reproduces that, so the SDK accepts the same proofs. The
SDK first tries the event exactly as written (stricter); the projection is a
fallback, and any fields it drops are reported as not covered by the hash.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any


class ModelError(ValueError):
    """The event does not fit the iOS model (the iOS app would fail to parse it)."""


@lru_cache(maxsize=1)
def ios_event_model() -> dict:
    raw = resources.files("verasnap_verify.data").joinpath("ios_event_model_1_6.json").read_text("utf-8")
    return json.loads(raw)["model"]


def _check_primitive(kind: str, value: Any, path: str) -> Any:
    if kind == "string":
        if not isinstance(value, str):
            raise ModelError(f"{path}: expected string")
    elif kind == "int":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) != int(value):
            raise ModelError(f"{path}: expected integer")
        value = int(value)
    elif kind == "double":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ModelError(f"{path}: expected number")
    elif kind == "bool":
        if not isinstance(value, bool):
            raise ModelError(f"{path}: expected boolean")
    return value


def _project(node: dict, value: Any, path: str, dropped: list[str]) -> Any:
    kind = node.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise ModelError(f"{path}: expected object")
        out = {}
        fields = node["fields"]
        for key in value:
            if key not in fields:
                dropped.append(f"{path}.{key}" if path else key)
        for key, spec in fields.items():
            present = key in value and value[key] is not None
            if not present:
                if spec["optional"]:
                    continue
                raise ModelError(f"{path}.{key}: required field missing" if path else f"{key}: required field missing")
            out[key] = _project(spec["schema"], value[key], f"{path}.{key}" if path else key, dropped)
        return out
    if kind == "array":
        if not isinstance(value, list):
            raise ModelError(f"{path}: expected array")
        return [_project(node["items"], v, f"{path}[{i}]", dropped) for i, v in enumerate(value)]
    if kind == "any":
        return value
    return _check_primitive(kind, value, path)


def project(event: dict) -> tuple[dict, list[str]]:
    """Return (projected event, dotted paths of dropped keys)."""
    dropped: list[str] = []
    out = _project(ios_event_model(), event, "", dropped)
    return out, dropped
