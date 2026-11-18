"""Verification result model.

Overall status follows the VeraSnap apps (iOS 1.6.1):

* any failed check -> red: SIGNATURE_INVALID, HASH_MISMATCH or ERROR;
* no failure but a warning -> yellow: PARTIALLY_VERIFIED;
* no failure, no warning, timestamp fully verified -> green: ANCHOR_VERIFIED;
* no failure, no warning, no fully verified timestamp -> yellow: ANCHOR_PENDING.

"skipped" (e.g. no photo supplied) and "info" checks do not change the status.
Green means only that the proof meets VeraSnap's verification criteria; the
capture time is the device clock's value and the content is not judged
("Provenance is not truth").
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"
    INFO = "info"


class Status(str, Enum):
    ANCHOR_VERIFIED = "ANCHOR_VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    ANCHOR_PENDING = "ANCHOR_PENDING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    HASH_MISMATCH = "HASH_MISMATCH"
    ERROR = "ERROR"

    @property
    def level(self) -> str:
        if self is Status.ANCHOR_VERIFIED:
            return "green"
        if self in (Status.PARTIALLY_VERIFIED, Status.ANCHOR_PENDING):
            return "yellow"
        return "red"


# Check identifiers (stable; integrators may key their own messages on them)
CHECK_PARSE = "parse"
CHECK_EVENT_HASH = "event_hash"
CHECK_SIGNATURE = "signature"
CHECK_SIGNER_KEY = "signer_key"
CHECK_MEDIA_HASH = "media_hash"
CHECK_MERKLE = "merkle_inclusion"
CHECK_IMPRINT = "message_imprint"
CHECK_TSA_SIGNATURE = "tsa_signature"
CHECK_TSA = "timestamp"
CHECK_CAPTURE_TIME = "capture_time"
CHECK_CHAIN_CONTEXT = "chain_context"
CHECK_ATTESTATION = "attestation"
CHECK_HUMAN_ATTESTATION = "human_attestation"

_HASH_CHECKS = {CHECK_EVENT_HASH, CHECK_MEDIA_HASH}


@dataclass
class Check:
    id: str
    status: CheckStatus
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Signer:
    public_key: str | None = None  # Base64 X9.63, as in the proof
    fingerprint: str | None = None  # SHA-256 hex of the X9.63 key
    known: bool = False
    account_ref: str | None = None
    platform: str | None = None
    security_level: str | None = None
    enrollment_status: str | None = None

    @property
    def short_fingerprint(self) -> str | None:
        return self.fingerprint[:16] if self.fingerprint else None


@dataclass
class VerificationResult:
    status: Status
    checks: list[Check]
    summary: str
    format: str | None = None  # "shareable" | "internal"
    proof_version: str | None = None
    proof_id: str | None = None
    event_id: str | None = None
    capture_time_device: str | None = None  # signed device-clock value, not proven
    timestamp_time: str | None = None  # genTime of a fully verified token only
    timestamp_authority: str | None = None
    media_verified: bool = False
    signer: Signer = field(default_factory=Signer)
    chain_context: dict | None = None  # as written in the proof; NOT covered by the signature
    sdk_version: str = ""
    rules: str = "verasnap-1.6.1"

    @property
    def level(self) -> str:
        return self.status.level

    def check(self, check_id: str) -> Check | None:
        for c in self.checks:
            if c.id == check_id:
                return c
        return None

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "level": self.level,
            "summary": self.summary,
            "format": self.format,
            "proof_version": self.proof_version,
            "proof_id": self.proof_id,
            "event_id": self.event_id,
            "capture_time_device": self.capture_time_device,
            "timestamp_time": self.timestamp_time,
            "timestamp_authority": self.timestamp_authority,
            "media_verified": self.media_verified,
            "signer": {**asdict(self.signer), "short_fingerprint": self.signer.short_fingerprint},
            "chain_context": self.chain_context,
            "checks": [c.to_dict() for c in self.checks],
            "sdk_version": self.sdk_version,
            "rules": self.rules,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def overall_status(checks: list[Check], *, timestamp_fully_verified: bool) -> Status:
    failed = [c for c in checks if c.status is CheckStatus.FAILED]
    warnings = [c for c in checks if c.status is CheckStatus.WARNING]
    if not failed:
        if warnings:
            return Status.PARTIALLY_VERIFIED
        return Status.ANCHOR_VERIFIED if timestamp_fully_verified else Status.ANCHOR_PENDING
    if any(c.id == CHECK_SIGNATURE for c in failed):
        return Status.SIGNATURE_INVALID
    if any(c.id in _HASH_CHECKS for c in failed):
        return Status.HASH_MISMATCH
    return Status.ERROR
