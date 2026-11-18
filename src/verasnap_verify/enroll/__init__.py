"""Device signing-key enrollment.

Flow (see docs/ENROLLMENT.md):

1. The insurer's server calls `Enroller.issue_challenge(account_ref)` for an
   authenticated customer session and sends the challenge to the app.
2. The capture SDK in the insurer's app creates a hardware signing key and
   returns an enrollment request (Android: Key Attestation chain made with the
   challenge; iOS: App Attest attestation whose clientDataHash commits to the
   challenge and the signing key), plus a proof-of-possession signature.
3. The server calls `Enroller.enroll(request, account_ref)`. On success the key
   is stored in the registry and later proofs signed with it are "known".
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from .._crypto import (
    CryptoInputError,
    b64decode,
    b64encode,
    key_fingerprint,
    load_p256_public_key,
    spki_der,
    utcnow,
    verify_es256,
    x963,
)
from ..registry import KeyRecord, KeyRegistry
from .android import AndroidPolicy, RevocationList, SecurityLevel, verify_android_attestation
from .apple import ApplePolicy, enrollment_client_data, verify_app_attest
from .errors import EnrollmentError

__all__ = [
    "AndroidPolicy",
    "ApplePolicy",
    "Challenge",
    "ChallengeStore",
    "EnrollmentError",
    "EnrollmentPolicy",
    "Enroller",
    "InMemoryChallengeStore",
    "RevocationList",
    "SecurityLevel",
    "POP_CONTEXT",
    "enrollment_client_data",
    "proof_of_possession_message",
]

POP_CONTEXT = b"VERASNAP-ENROLL-POP-v1\x00"
ENROLLMENT_VERSION = 1


def proof_of_possession_message(challenge: bytes) -> bytes:
    """Message the app signs with the new signing key (ES256) to prove it holds it."""
    return POP_CONTEXT + challenge


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    nonce: bytes
    account_ref: str
    expires_at: datetime

    def to_wire(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "challenge": b64encode(self.nonce),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


class ChallengeStore:
    def save(self, challenge: Challenge) -> None:
        raise NotImplementedError

    def consume(self, challenge_id: str) -> Challenge | None:
        """Return and delete the challenge (single use)."""
        raise NotImplementedError


class InMemoryChallengeStore(ChallengeStore):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Challenge] = {}

    def save(self, challenge: Challenge) -> None:
        with self._lock:
            now = utcnow()
            for key in [k for k, v in self._items.items() if v.expires_at < now]:
                del self._items[key]
            self._items[challenge.challenge_id] = challenge

    def consume(self, challenge_id: str) -> Challenge | None:
        with self._lock:
            return self._items.pop(challenge_id, None)


@dataclass(frozen=True)
class EnrollmentPolicy:
    android: AndroidPolicy | None = None
    apple: ApplePolicy | None = None
    challenge_ttl: timedelta = timedelta(minutes=5)
    require_proof_of_possession: bool = True


@dataclass
class Enroller:
    policy: EnrollmentPolicy
    registry: KeyRegistry
    challenges: ChallengeStore = field(default_factory=InMemoryChallengeStore)

    def issue_challenge(self, account_ref: str) -> Challenge:
        if not account_ref:
            raise ValueError("account_ref is required")
        challenge = Challenge(
            challenge_id=os.urandom(16).hex(),
            nonce=os.urandom(32),
            account_ref=account_ref,
            expires_at=utcnow() + self.policy.challenge_ttl,
        )
        self.challenges.save(challenge)
        return challenge

    def enroll(self, request: Mapping[str, Any], account_ref: str, *, now: datetime | None = None) -> KeyRecord:
        """Verify an enrollment request and store the key.

        `account_ref` must come from the insurer's own authenticated session,
        never from the request body.
        """
        now = now or utcnow()
        if request.get("enrollment_version", ENROLLMENT_VERSION) != ENROLLMENT_VERSION:
            raise EnrollmentError("unsupported_version", "unsupported enrollment_version")
        challenge = self.challenges.consume(str(request.get("challenge_id", "")))
        if challenge is None:
            raise EnrollmentError("challenge_unknown", "challenge is unknown or was already used")
        if challenge.expires_at < now:
            raise EnrollmentError("challenge_expired", "challenge has expired")
        if challenge.account_ref != account_ref:
            raise EnrollmentError("challenge_mismatch", "challenge was issued to a different account")

        try:
            key = load_p256_public_key(b64decode(request.get("signing_public_key", ""), field="signing_public_key"))
        except CryptoInputError as exc:
            raise EnrollmentError("request_malformed", str(exc)) from exc
        key_x963 = x963(key)

        pop = request.get("proof_of_possession")
        if pop:
            try:
                pop_sig = b64decode(pop, field="proof_of_possession")
            except CryptoInputError as exc:
                raise EnrollmentError("request_malformed", str(exc)) from exc
            if not verify_es256(key, pop_sig, proof_of_possession_message(challenge.nonce)):
                raise EnrollmentError("proof_of_possession_invalid", "proof-of-possession signature is not valid")
        elif self.policy.require_proof_of_possession:
            raise EnrollmentError("proof_of_possession_missing", "proof_of_possession is required")

        platform = request.get("platform")
        attestation: dict
        record_extra: dict = {}
        if platform == "android":
            if self.policy.android is None:
                raise EnrollmentError("platform_not_allowed", "Android enrollment is not enabled")
            android = request.get("android") or {}
            try:
                chain = [b64decode(c, field="attestation_chain") for c in android.get("attestation_chain", [])]
            except CryptoInputError as exc:
                raise EnrollmentError("request_malformed", str(exc)) from exc
            result = verify_android_attestation(chain, spki_der(key), challenge.nonce, self.policy.android, now=now)
            attestation = result.summary()
            security_level = result.keymint_security_level.label
        elif platform == "ios":
            if self.policy.apple is None:
                raise EnrollmentError("platform_not_allowed", "iOS enrollment is not enabled")
            ios = request.get("ios") or {}
            try:
                key_id = b64decode(ios.get("app_attest_key_id", ""), field="app_attest_key_id")
                att_obj = b64decode(ios.get("attestation_object", ""), field="attestation_object")
            except CryptoInputError as exc:
                raise EnrollmentError("request_malformed", str(exc)) from exc
            client_data_hash = hashlib.sha256(enrollment_client_data(challenge.nonce, key_x963)).digest()
            result = verify_app_attest(att_obj, key_id, client_data_hash, self.policy.apple, now=now)
            attestation = result.summary()
            attestation["app_attest_public_key"] = b64encode(x963(result.public_key))
            record_extra["app_attest_sign_count"] = 0
            # The signing key itself lives in the Secure Enclave; Apple attests
            # the app instance that asked to enroll it.
            security_level = "SECURE_ENCLAVE_STATED"
        else:
            raise EnrollmentError("request_malformed", "platform must be 'android' or 'ios'")

        fingerprint = key_fingerprint(key)
        existing = self.registry.get(fingerprint)
        if existing is not None and existing.account_ref != account_ref:
            raise EnrollmentError("key_already_enrolled", "this key is already enrolled to another account")

        record = KeyRecord(
            fingerprint=fingerprint,
            public_key_x963=b64encode(key_x963),
            platform=platform,
            account_ref=account_ref,
            security_level=security_level,
            enrolled_at=now.isoformat().replace("+00:00", "Z"),
            attestation=attestation,
            **record_extra,
        )
        self.registry.put(record)
        return record
