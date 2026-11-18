"""Minimal DER reader.

Used for structures whose schemas keep growing (Android KeyDescription,
Apple App Attest extensions), where a strict schema parser would reject
data from newer devices. Only definite-length DER is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_ENUMERATED = 10
TAG_SEQUENCE = 16
TAG_SET = 17


class DERError(ValueError):
    """Raised when bytes are not valid DER for the expected shape."""


@dataclass(frozen=True)
class TLV:
    cls: int
    constructed: bool
    tag: int
    value: bytes
    raw: bytes

    def children(self) -> list["TLV"]:
        if not self.constructed:
            raise DERError("primitive element has no children")
        return parse_all(self.value)

    def is_universal(self, tag: int) -> bool:
        return self.cls == UNIVERSAL and self.tag == tag


def _read(buf: bytes, pos: int) -> tuple[TLV, int]:
    start = pos
    if pos >= len(buf):
        raise DERError("truncated tag")
    first = buf[pos]
    pos += 1
    cls = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if pos >= len(buf):
                raise DERError("truncated high tag number")
            octet = buf[pos]
            pos += 1
            tag = (tag << 7) | (octet & 0x7F)
            if tag > (1 << 28):
                raise DERError("tag number too large")
            if not octet & 0x80:
                break
    if pos >= len(buf):
        raise DERError("truncated length")
    length = buf[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0:
            raise DERError("indefinite length is not DER")
        if count > 4:
            raise DERError("length too large")
        if pos + count > len(buf):
            raise DERError("truncated length")
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(buf):
        raise DERError("truncated value")
    return TLV(cls, constructed, tag, bytes(buf[pos:end]), bytes(buf[start:end])), end


def parse_one(buf: bytes) -> TLV:
    tlv, end = _read(buf, 0)
    if end != len(buf):
        raise DERError("trailing data after element")
    return tlv


def parse_all(buf: bytes) -> list[TLV]:
    items: list[TLV] = []
    pos = 0
    while pos < len(buf):
        tlv, pos = _read(buf, pos)
        items.append(tlv)
    return items


def as_int(tlv: TLV) -> int:
    if not (tlv.is_universal(TAG_INTEGER) or tlv.is_universal(TAG_ENUMERATED)):
        raise DERError(f"expected INTEGER or ENUMERATED, got class {tlv.cls} tag {tlv.tag}")
    if not tlv.value:
        raise DERError("empty INTEGER")
    return int.from_bytes(tlv.value, "big", signed=True)


def as_bool(tlv: TLV) -> bool:
    if not tlv.is_universal(TAG_BOOLEAN) or len(tlv.value) != 1:
        raise DERError("expected BOOLEAN")
    return tlv.value != b"\x00"


def as_octets(tlv: TLV) -> bytes:
    if not tlv.is_universal(TAG_OCTET_STRING):
        raise DERError("expected OCTET STRING")
    return tlv.value


def as_int_set(tlv: TLV) -> list[int]:
    if not tlv.is_universal(TAG_SET):
        raise DERError("expected SET OF INTEGER")
    return [as_int(child) for child in tlv.children()]
