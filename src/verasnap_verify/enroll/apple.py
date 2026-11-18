"""Apple App Attest verification for signing-key enrollment.

iOS cannot attest a Secure Enclave signing key directly. Instead the app
asks App Attest to attest its own App Attest key with a clientDataHash
that commits to the server challenge *and* the signing public key
(see `enrollment_client_data`). A valid attestation therefore shows that
a genuine instance of the expected app, on a genuine Apple device,
asked to enroll that signing key.

Reference: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from typing import Sequence

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

from .. import _der
from .._crypto import (
    ChainError,
    CryptoInputError,
    build_path,
    load_certificate,
    utcnow,
    verify_es256,
    x963,
)
from .errors import EnrollmentError

OID_APPLE_NONCE = ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"

ENROLL_CONTEXT = b"VERASNAP-ENROLL-v1\x00"


def enrollment_client_data(challenge: bytes, signing_public_key_x963: bytes) -> bytes:
    """The data block whose SHA-256 the app passes to `attestKey` as clientDataHash.

    Layout: "VERASNAP-ENROLL-v1" || 0x00 || challenge || signing key (65-byte X9.63).
    """
    return ENROLL_CONTEXT + challenge + signing_public_key_x963


def apple_app_attest_root() -> x509.Certificate:
    """Apple App Attestation Root CA, bundled with the SDK.

    Source: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
    SHA-256 1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932.
    """
    pem = resources.files("verasnap_verify.data").joinpath("apple_app_attestation_root_ca.pem").read_bytes()
    return load_certificate(pem)


@dataclass(frozen=True)
class AppAttestKey:
    key_id: bytes
    public_key: ec.EllipticCurvePublicKey
    environment: str  # "production" or "development"
    sign_count: int
    receipt: bytes

    def summary(self) -> dict:
        return {
            "type": "apple_app_attest",
            "environment": self.environment,
            "app_attest_key_id": self.key_id.hex(),
        }


@dataclass(frozen=True)
class ApplePolicy:
    app_ids: Sequence[str]  # "TEAMID.bundle.identifier"
    allow_development: bool = False
    trusted_roots: Sequence[x509.Certificate] | None = None


@dataclass(frozen=True)
class _AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None
    credential_id: bytes | None


def _parse_auth_data(data: bytes, *, attested: bool) -> _AuthData:
    if len(data) < 37:
        raise EnrollmentError("attestation_malformed", "authenticator data is too short")
    rp_id_hash = data[:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    if not attested:
        return _AuthData(rp_id_hash, flags, sign_count, None, None)
    if len(data) < 55:
        raise EnrollmentError("attestation_malformed", "attested credential data is missing")
    aaguid = data[37:53]
    cred_len = int.from_bytes(data[53:55], "big")
    cred_id = data[55 : 55 + cred_len]
    if len(cred_id) != cred_len:
        raise EnrollmentError("attestation_malformed", "credential id is truncated")
    return _AuthData(rp_id_hash, flags, sign_count, aaguid, cred_id)


def _nonce_from_extension(cert: x509.Certificate) -> bytes:
    try:
        ext = cert.extensions.get_extension_for_oid(OID_APPLE_NONCE).value
    except x509.ExtensionNotFound as exc:
        raise EnrollmentError("attestation_malformed", "credential certificate has no App Attest nonce") from exc
    try:
        seq = _der.parse_one(ext.value)
        for item in seq.children():
            if item.cls == _der.CONTEXT and item.tag == 1:
                return _der.as_octets(_der.parse_one(item.value))
    except _der.DERError as exc:
        raise EnrollmentError("attestation_malformed", f"App Attest nonce: {exc}") from exc
    raise EnrollmentError("attestation_malformed", "App Attest nonce not found")


def _rp_id_ok(rp_id_hash: bytes, app_ids: Sequence[str]) -> str | None:
    for app_id in app_ids:
        if hashlib.sha256(app_id.encode("utf-8")).digest() == rp_id_hash:
            return app_id
    return None


def verify_app_attest(
    attestation_object: bytes,
    key_id: bytes,
    client_data_hash: bytes,
    policy: ApplePolicy,
    *,
    now: datetime | None = None,
) -> AppAttestKey:
    """Verify an App Attest attestation object (steps 1–9 of Apple's guide)."""
    now = now or utcnow()
    try:
        obj = cbor2.loads(attestation_object)
    except Exception as exc:  # cbor2 raises several types
        raise EnrollmentError("attestation_malformed", "attestation object is not valid CBOR") from exc
    if not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
        raise EnrollmentError("attestation_malformed", "attestation format is not apple-appattest")
    stmt = obj.get("attStmt") or {}
    x5c = stmt.get("x5c") or []
    auth_data = obj.get("authData")
    if len(x5c) < 2 or not isinstance(auth_data, bytes):
        raise EnrollmentError("attestation_malformed", "attestation statement is incomplete")
    try:
        certs = [load_certificate(bytes(c)) for c in x5c]
    except CryptoInputError as exc:
        raise EnrollmentError("attestation_malformed", str(exc)) from exc

    roots = list(policy.trusted_roots) if policy.trusted_roots is not None else [apple_app_attest_root()]
    try:
        build_path(certs[0], certs[1:], roots, at=now)
    except ChainError as exc:
        raise EnrollmentError("attestation_untrusted_root", f"App Attest chain: {exc}") from exc

    cred_cert = certs[0]
    expected_nonce = hashlib.sha256(auth_data + client_data_hash).digest()
    if _nonce_from_extension(cred_cert) != expected_nonce:
        raise EnrollmentError("challenge_mismatch", "App Attest nonce does not match the client data")

    pub = cred_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise EnrollmentError("attestation_malformed", "App Attest key is not an EC key")
    if hashlib.sha256(x963(pub)).digest() != key_id:
        raise EnrollmentError("attestation_key_mismatch", "App Attest key id does not match the attested key")

    ad = _parse_auth_data(auth_data, attested=True)
    if _rp_id_ok(ad.rp_id_hash, policy.app_ids) is None:
        raise EnrollmentError("app_mismatch", "App ID does not match any allowed app")
    if ad.sign_count != 0:
        raise EnrollmentError("attestation_malformed", "attestation counter is not zero")
    if ad.aaguid == AAGUID_PRODUCTION:
        environment = "production"
    elif ad.aaguid == AAGUID_DEVELOPMENT:
        if not policy.allow_development:
            raise EnrollmentError("app_mismatch", "development App Attest environment is not allowed")
        environment = "development"
    else:
        raise EnrollmentError("attestation_malformed", "unknown App Attest environment")
    if ad.credential_id != key_id:
        raise EnrollmentError("attestation_key_mismatch", "credential id does not match the key id")

    return AppAttestKey(
        key_id=key_id,
        public_key=pub,
        environment=environment,
        sign_count=0,
        receipt=bytes(stmt.get("receipt") or b""),
    )


def verify_app_attest_assertion(
    assertion: bytes,
    client_data_hash: bytes,
    app_attest_public_key: ec.EllipticCurvePublicKey,
    app_ids: Sequence[str],
    previous_sign_count: int,
) -> int:
    """Verify a later App Attest assertion; returns the new counter to store."""
    try:
        obj = cbor2.loads(assertion)
    except Exception as exc:
        raise EnrollmentError("assertion_malformed", "assertion is not valid CBOR") from exc
    signature = obj.get("signature") if isinstance(obj, dict) else None
    auth_data = obj.get("authenticatorData") if isinstance(obj, dict) else None
    if not isinstance(signature, bytes) or not isinstance(auth_data, bytes):
        raise EnrollmentError("assertion_malformed", "assertion is incomplete")
    nonce = hashlib.sha256(auth_data + client_data_hash).digest()
    if not verify_es256(app_attest_public_key, signature, nonce):
        raise EnrollmentError("assertion_invalid", "assertion signature is not valid")
    ad = _parse_auth_data(auth_data, attested=False)
    if _rp_id_ok(ad.rp_id_hash, app_ids) is None:
        raise EnrollmentError("app_mismatch", "App ID does not match any allowed app")
    if ad.sign_count <= previous_sign_count:
        raise EnrollmentError("assertion_replayed", "assertion counter did not increase")
    return ad.sign_count
