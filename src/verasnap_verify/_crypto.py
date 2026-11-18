"""Shared cryptographic helpers: P-256 keys, ES256 signatures, X.509 chains."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class CryptoInputError(ValueError):
    """Input could not be decoded (bad Base64, bad key, bad certificate)."""


# ---------------------------------------------------------------- encodings


def b64decode(value: str | bytes, *, field: str = "value") -> bytes:
    """Decode standard or URL-safe Base64, with or without padding."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "strict")
    text = "".join(value.split())
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoInputError(f"{field}: not valid Base64") from exc


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------- P-256 keys


def load_p256_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from X9.63 (uncompressed or compressed) or SPKI DER."""
    try:
        if data[:1] in (b"\x02", b"\x03", b"\x04") and len(data) in (33, 65):
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
        else:
            key = serialization.load_der_public_key(data)
    except (ValueError, TypeError, IndexError) as exc:
        raise CryptoInputError("public key: not a P-256 key in X9.63 or SPKI form") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise CryptoInputError("public key: not a P-256 (secp256r1) key")
    return key


def x963(key: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed X9.63 point (65 bytes), the form VeraSnap exports."""
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def key_fingerprint(key: ec.EllipticCurvePublicKey) -> str:
    """Full SHA-256 of the uncompressed X9.63 point, lowercase hex.

    The VeraSnap apps display the first 8 bytes of this value.
    """
    return hashlib.sha256(x963(key)).hexdigest()


def short_fingerprint(fingerprint_hex: str) -> str:
    return fingerprint_hex[:16]


def verify_es256(key: ec.EllipticCurvePublicKey, signature: bytes, message: bytes) -> bool:
    """Verify an ES256 signature given either raw r||s (64 bytes) or DER."""
    candidates: list[bytes] = []
    if len(signature) == 64:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        candidates.append(encode_dss_signature(r, s))
    candidates.append(signature)
    for der in candidates:
        try:
            key.verify(der, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


# ---------------------------------------------------------------- X.509


def load_certificate(data: bytes) -> x509.Certificate:
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CryptoInputError("certificate: not a valid X.509 certificate") from exc


def load_pem_bundle(data: bytes) -> list[x509.Certificate]:
    return list(x509.load_pem_x509_certificates(data))


def spki_der(cert_or_key) -> bytes:
    key = cert_or_key.public_key() if isinstance(cert_or_key, x509.Certificate) else cert_or_key
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def cert_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def verify_signed_by(cert: x509.Certificate, issuer_key) -> bool:
    """True if `cert` carries a valid signature made with `issuer_key`."""
    params = cert.signature_algorithm_parameters
    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, params, cert.signature_hash_algorithm)
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, params)
        elif isinstance(issuer_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def is_valid_at(cert: x509.Certificate, when: datetime, *, skew: timedelta = timedelta(0)) -> bool:
    return cert.not_valid_before_utc - skew <= when <= cert.not_valid_after_utc + skew


def is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return bool(bc.ca)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ChainResult:
    path: tuple[x509.Certificate, ...]  # leaf first, trust anchor last
    anchor: x509.Certificate


class ChainError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def build_path(
    leaf: x509.Certificate,
    candidates: Iterable[x509.Certificate],
    anchors: Sequence[x509.Certificate],
    *,
    at: datetime,
    max_depth: int = 8,
    require_ca_intermediates: bool = True,
) -> ChainResult:
    """Build and check a path from `leaf` to one of `anchors`, valid at time `at`.

    Issuers are matched by name and confirmed by signature. Trust anchors are
    matched by subject and public key, so a cross-certified copy of a root in
    `candidates` cannot replace the anchor.
    """
    anchor_keys = {spki_der(a): a for a in anchors}
    pool = [c for c in candidates if c != leaf]
    path = [leaf]
    current = leaf
    if not is_valid_at(leaf, at):
        raise ChainError("cert_expired", f"certificate '{leaf.subject.rfc4514_string()}' is not valid at {at.isoformat()}")
    for _ in range(max_depth):
        own = anchor_keys.get(spki_der(current))
        if own is not None and own.subject == current.subject:
            return ChainResult(tuple(path[:-1]) + (own,), own)
        issuer = None
        for anchor in anchors:
            if anchor.subject == current.issuer and verify_signed_by(current, anchor.public_key()):
                issuer = anchor
                break
        if issuer is not None:
            if not is_valid_at(issuer, at):
                raise ChainError("cert_expired", f"trust anchor '{issuer.subject.rfc4514_string()}' is not valid at {at.isoformat()}")
            return ChainResult(tuple(path) + (issuer,), issuer)
        for cand in pool:
            if cand in path or cand.subject != current.issuer:
                continue
            if not verify_signed_by(current, cand.public_key()):
                continue
            if require_ca_intermediates and not is_ca(cand):
                continue
            issuer = cand
            break
        if issuer is None:
            raise ChainError("untrusted_chain", f"no trusted issuer found for '{current.subject.rfc4514_string()}'")
        if not is_valid_at(issuer, at):
            raise ChainError("cert_expired", f"certificate '{issuer.subject.rfc4514_string()}' is not valid at {at.isoformat()}")
        path.append(issuer)
        current = issuer
    raise ChainError("chain_too_long", "certificate chain is too long")
