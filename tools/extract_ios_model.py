#!/usr/bin/env python3
"""Extract the field tree of VeraSnap iOS `CPPEventJSON` from the Swift sources.

The iOS verifier recomputes the EventHash of an internal proof.json by
decoding the event into `CPPEventJSON` (unknown keys are dropped, nil
optionals are omitted) and canonicalizing the re-encoded dictionary. The SDK
reproduces that as a fallback, and needs the exact key tree to do so.

Usage: extract_ios_model.py <path to "Sources 2"> <output.json>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PRIMITIVES = {
    "String": "string",
    "Int": "int",
    "Int64": "int",
    "Int32": "int",
    "UInt": "int",
    "Double": "double",
    "Float": "double",
    "CGFloat": "double",
    "Bool": "bool",
    "Date": "string",
}


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def blocks(src: str, kind: str, name: str) -> list[str]:
    out = []
    for m in re.finditer(rf"\b{kind}\s+{name}\b[^{{]*\{{", src):
        i, depth = m.end(), 1
        while depth:
            c = src[i]
            depth += c == "{"
            depth -= c == "}"
            i += 1
        out.append(src[m.start() : i])
    return out


def top_level_body(block: str) -> str:
    """Body of a type with nested braces (methods, nested types) removed."""
    body = block[block.index("{") + 1 : -1]
    out, depth = [], 0
    for ch in body:
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


class Extractor:
    def __init__(self, src: str):
        self.src = strip_comments(src)
        self.cache: dict[str, dict] = {}

    def enum_raw_type(self, name: str) -> str | None:
        found = blocks(self.src, "enum", name)
        if not found:
            return None
        head = found[0][: found[0].index("{")]
        if re.search(r":\s*String\b", head):
            return "string"
        if re.search(r":\s*Int\b", head):
            return "int"
        return "any"

    def type_node(self, t: str) -> dict:
        t = t.strip()
        if t.startswith("[") and t.endswith("]"):
            inner = t[1:-1]
            if ":" in inner:
                return {"type": "any"}
            return {"type": "array", "items": self.type_node(inner)}
        if t in PRIMITIVES:
            return {"type": PRIMITIVES[t]}
        return self.struct(t)

    def struct(self, name: str) -> dict:
        if name in self.cache:
            return self.cache[name]
        found = blocks(self.src, "struct", name)
        if not found:
            raw = self.enum_raw_type(name)
            node = {"type": raw or "any", "swift": name}
            self.cache[name] = node
            return node
        if len(found) > 1:
            sys.stderr.write(f"warning: {name} defined {len(found)} times, using the first\n")
        block = found[0]
        if re.search(r"func\s+encode\s*\(\s*to\s+encoder", block) or re.search(r"init\s*\(\s*from\s+decoder", block):
            sys.stderr.write(f"warning: {name} has custom Codable code; check the generated node by hand\n")
        body = top_level_body(block)
        props: dict[str, tuple[str, bool]] = {}
        for m in re.finditer(r"\b(?:let|var)\s+(\w+)\s*:\s*([^\n=]+)", body):
            pname, ptype = m.group(1), m.group(2).strip()
            if re.search(r"\bstatic\b", body[max(0, m.start() - 20) : m.start()]):
                continue
            optional = ptype.endswith("?")
            props[pname] = (ptype.rstrip("?").strip(), optional)
        keys: dict[str, str] = {}
        ck = blocks(block, "enum", "CodingKeys")
        if ck:
            for m in re.finditer(r"case\s+([^\n]+)", top_level_body(ck[0])):
                for part in m.group(1).split(","):
                    part = part.strip()
                    if not part:
                        continue
                    mm = re.match(r"(\w+)\s*(?:=\s*\"([^\"]*)\")?", part)
                    if mm:
                        keys[mm.group(1)] = mm.group(2) or mm.group(1)
        else:
            keys = {p: p for p in props}
        node = {"type": "object", "swift": name, "fields": {}}
        self.cache[name] = node
        for prop, json_key in keys.items():
            if prop not in props:
                sys.stderr.write(f"warning: {name}.{prop} has a coding key but no stored property\n")
                continue
            ptype, optional = props[prop]
            node["fields"][json_key] = {"optional": optional, "schema": self.type_node(ptype)}
        return node


def main() -> int:
    src_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
    src = "\n".join(p.read_text(encoding="utf-8") for p in sorted(src_dir.rglob("*.swift")))
    ex = Extractor(src)
    model = ex.struct("CPPEventJSON")
    doc = {
        "description": "Field tree of VeraSnap iOS CPPEventJSON (legacy EventHash fallback). Generated; do not edit.",
        "source": "veritaschain/verasnap-ios, Sources 2/Verification/ProofModels.swift and referenced types",
        "model": model,
    }
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
