"""Android Key Attestation verification for signing-key enrollment.

Checks that a P-256 signing key was generated inside Android Keystore
hardware (TEE or StrongBox), for the expected app, on a device with a
verified boot state, in response to a fresh server challenge.

Reference: https://developer.android.com/privacy-and-security/security-key-attestation
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from importlib import resources
from typing import Mapping, Sequence

from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

from .. import _der
from .._crypto import is_valid_at, load_certificate, spki_der, utcnow
from .errors import EnrollmentError

OID_KEY_DESCRIPTION = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# Keymaster / KeyMint tag numbers (AuthorizationList context tags)
TAG_PURPOSE = 1
TAG_ALGORITHM = 2
TAG_KEY_SIZE = 3
TAG_DIGEST = 5
TAG_EC_CURVE = 10
TAG_NO_AUTH_REQUIRED = 503
TAG_CREATION_DATETIME = 701
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719

KM_PURPOSE_SIGN = 2
KM_ALGORITHM_EC = 3
KM_EC_CURVE_P_256 = 1
KM_ORIGIN_GENERATED = 0


class SecurityLevel(IntEnum):
    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1
    STRONGBOX = 2

    @property
    def label(self) -> str:
        return {0: "SOFTWARE", 1: "TEE", 2: "STRONGBOX"}[int(self)]

    @classmethod
    def parse(cls, value: "str | int | SecurityLevel") -> "SecurityLevel":
        if isinstance(value, SecurityLevel):
            return value
        if isinstance(value, int):
            return cls(value)
        names = {"SOFTWARE": 0, "TEE": 1, "TRUSTED_ENVIRONMENT": 1, "STRONGBOX": 2}
        try:
            return cls(names[value.strip().upper()])
        except KeyError as exc:
            raise ValueError(f"unknown security level: {value!r}") from exc


class VerifiedBootState(IntEnum):
    VERIFIED = 0
    SELF_SIGNED = 1
    UNVERIFIED = 2
    FAILED = 3


@dataclass(frozen=True)
class RootOfTrust:
    verified_boot_key: bytes
    device_locked: bool
    verified_boot_state: VerifiedBootState
    verified_boot_hash: bytes | None


@dataclass(frozen=True)
class AttestationApplicationId:
    package_names: tuple[str, ...]
    signature_digests: tuple[bytes, ...]


@dataclass
class AuthorizationList:
    purposes: list[int] = field(default_factory=list)
    algorithm: int | None = None
    key_size: int | None = None
    digests: list[int] = field(default_factory=list)
    ec_curve: int | None = None
    no_auth_required: bool = False
    origin: int | None = None
    root_of_trust: RootOfTrust | None = None
    os_version: int | None = None
    os_patch_level: int | None = None
    vendor_patch_level: int | None = None
    boot_patch_level: int | None = None
    creation_datetime_ms: int | None = None
    application_id: AttestationApplicationId | None = None
    unknown_tags: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class KeyDescription:
    attestation_version: int
    attestation_security_level: SecurityLevel
    keymint_version: int
    keymint_security_level: SecurityLevel
    attestation_challenge: bytes
    unique_id: bytes
    software_enforced: AuthorizationList
    hardware_enforced: AuthorizationList

    def lookup(self, name: str):
        """Hardware-enforced value first, software-enforced as fallback."""
        hw = getattr(self.hardware_enforced, name)
        if hw not in (None, [], False):
            return hw
        return getattr(self.software_enforced, name)


# ---------------------------------------------------------------- parsing


def _parse_root_of_trust(tlv: _der.TLV) -> RootOfTrust:
    items = tlv.children()
    if len(items) < 3:
        raise _der.DERError("RootOfTrust: too few fields")
    return RootOfTrust(
        verified_boot_key=_der.as_octets(items[0]),
        device_locked=_der.as_bool(items[1]),
        verified_boot_state=VerifiedBootState(_der.as_int(items[2])),
        verified_boot_hash=_der.as_octets(items[3]) if len(items) > 3 else None,
    )


def _parse_application_id(octets: bytes) -> AttestationApplicationId:
    seq = _der.parse_one(octets)
    parts = seq.children()
    if len(parts) != 2:
        raise _der.DERError("AttestationApplicationId: expected 2 fields")
    names = []
    for info in parts[0].children():
        fields = info.children()
        names.append(_der.as_octets(fields[0]).decode("utf-8", "replace"))
    digests = [_der.as_octets(d) for d in parts[1].children()]
    return AttestationApplicationId(tuple(names), tuple(digests))


def _parse_authorization_list(tlv: _der.TLV) -> AuthorizationList:
    if not tlv.is_universal(_der.TAG_SEQUENCE):
        raise _der.DERError("AuthorizationList: expected SEQUENCE")
    out = AuthorizationList()
    for item in tlv.children():
        if item.cls != _der.CONTEXT or not item.constructed:
            raise _der.DERError("AuthorizationList: expected explicit context tag")
        inner = _der.parse_one(item.value)
        tag = item.tag
        if tag == TAG_PURPOSE:
            out.purposes = _der.as_int_set(inner)
        elif tag == TAG_ALGORITHM:
            out.algorithm = _der.as_int(inner)
        elif tag == TAG_KEY_SIZE:
            out.key_size = _der.as_int(inner)
        elif tag == TAG_DIGEST:
            out.digests = _der.as_int_set(inner)
        elif tag == TAG_EC_CURVE:
            out.ec_curve = _der.as_int(inner)
        elif tag == TAG_NO_AUTH_REQUIRED:
            out.no_auth_required = True
        elif tag == TAG_ORIGIN:
            out.origin = _der.as_int(inner)
        elif tag == TAG_ROOT_OF_TRUST:
            out.root_of_trust = _parse_root_of_trust(inner)
        elif tag == TAG_OS_VERSION:
            out.os_version = _der.as_int(inner)
        elif tag == TAG_OS_PATCH_LEVEL:
            out.os_patch_level = _der.as_int(inner)
        elif tag == TAG_VENDOR_PATCH_LEVEL:
            out.vendor_patch_level = _der.as_int(inner)
        elif tag == TAG_BOOT_PATCH_LEVEL:
            out.boot_patch_level = _der.as_int(inner)
        elif tag == TAG_CREATION_DATETIME:
            out.creation_datetime_ms = _der.as_int(inner)
        elif tag == TAG_ATTESTATION_APPLICATION_ID:
            out.application_id = _parse_application_id(_der.as_octets(inner))
        else:
            out.unknown_tags.append(tag)
    return out


def parse_key_description(der: bytes) -> KeyDescription:
    seq = _der.parse_one(der)
    if not seq.is_universal(_der.TAG_SEQUENCE):
        raise _der.DERError("KeyDescription: expected SEQUENCE")
    f = seq.children()
    if len(f) < 8:
        raise _der.DERError("KeyDescription: too few fields")
    return KeyDescription(
        attestation_version=_der.as_int(f[0]),
        attestation_security_level=SecurityLevel(_der.as_int(f[1])),
        keymint_version=_der.as_int(f[2]),
        keymint_security_level=SecurityLevel(_der.as_int(f[3])),
        attestation_challenge=_der.as_octets(f[4]),
        unique_id=_der.as_octets(f[5]),
        software_enforced=_parse_authorization_list(f[6]),
        hardware_enforced=_parse_authorization_list(f[7]),
    )


# ---------------------------------------------------------------- roots and revocation


def google_attestation_roots() -> list[x509.Certificate]:
    """Google hardware attestation roots bundled with the SDK.

    Source: https://android.googleapis.com/attestation/root (fetched 2026-11-18).
    """
    raw = resources.files("verasnap_verify.data").joinpath("google_attestation_roots.json").read_text("utf-8")
    return [load_certificate(pem.encode()) for pem in json.loads(raw)]


@dataclass(frozen=True)
class RevocationList:
    """Google's attestation certificate status list.

    Load the JSON from https://android.googleapis.com/attestation/status
    (refresh it daily) and pass it in; the SDK does no network I/O itself.
    """

    entries: Mapping[str, Mapping[str, str]]

    @classmethod
    def from_json(cls, data: str | bytes) -> "RevocationList":
        doc = json.loads(data)
        return cls({k.lower(): v for k, v in doc.get("entries", {}).items()})

    def status(self, cert: x509.Certificate) -> str | None:
        return self.status_of_serial(cert.serial_number)

    def status_of_serial(self, serial: int) -> str | None:
        entry = self.entries.get(format(serial, "x"))
        return entry.get("status") if entry else None


# ---------------------------------------------------------------- lenient certificates


_SIG_HASHES = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


@dataclass(frozen=True)
class _AttCert:
    """An attestation certificate parsed leniently.

    Some devices (seen on StrongBox) emit certificates that strict parsers
    reject, e.g. an ECDSA AlgorithmIdentifier with NULL parameters. The bytes
    that are signed (TBSCertificate) are kept exactly as received.
    """

    tbs: bytes
    signature: bytes
    signature_algo: str
    hash_algo: str | None
    public_key: object
    spki: bytes
    not_before: datetime
    not_after: datetime
    serial: int
    subject: str
    key_description: bytes | None

    @classmethod
    def load(cls, der: bytes) -> "_AttCert":
        cert = a_x509.Certificate.load(der)
        tbs = cert["tbs_certificate"]
        key = serialization.load_der_public_key(tbs["subject_public_key_info"].dump())
        sig_alg = cert["signature_algorithm"]
        try:
            hash_algo = sig_alg.hash_algo
        except (ValueError, KeyError):
            hash_algo = None
        kd = None
        for ext in tbs["extensions"] or []:
            if ext["extn_id"].dotted == OID_KEY_DESCRIPTION.dotted_string:
                kd = ext["extn_value"].contents
        validity = tbs["validity"]
        return cls(
            tbs=tbs.dump(),
            signature=cert["signature_value"].native,
            signature_algo=sig_alg.signature_algo,
            hash_algo=hash_algo,
            public_key=key,
            spki=key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            not_before=validity["not_before"].native,
            not_after=validity["not_after"].native,
            serial=tbs["serial_number"].native,
            subject=cert.subject.human_friendly,
            key_description=kd,
        )

    def valid_at(self, when: datetime, skew: timedelta) -> bool:
        return self.not_before - skew <= when <= self.not_after + skew

    def signed_by(self, issuer_key) -> bool:
        try:
            if self.signature_algo == "rsassa_pss":
                return False  # not used by attestation chains
            algo = _SIG_HASHES.get(self.hash_algo or "")
            if algo is None:
                return False
            if isinstance(issuer_key, rsa.RSAPublicKey) and self.signature_algo == "rsassa_pkcs1v15":
                issuer_key.verify(self.signature, self.tbs, padding.PKCS1v15(), algo())
            elif isinstance(issuer_key, ec.EllipticCurvePublicKey) and self.signature_algo == "ecdsa":
                issuer_key.verify(self.signature, self.tbs, ec.ECDSA(algo()))
            else:
                return False
        except (InvalidSignature, ValueError):
            return False
        return True


# ---------------------------------------------------------------- verification


@dataclass(frozen=True)
class AndroidPolicy:
    package_names: Sequence[str]
    signing_cert_sha256: Sequence[bytes]
    min_security_level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT
    require_verified_boot: bool = True
    require_locked_bootloader: bool = True
    trusted_roots: Sequence[x509.Certificate] | None = None
    revocation: RevocationList | None = None
    clock_skew: timedelta = timedelta(minutes=5)


@dataclass(frozen=True)
class AndroidAttestation:
    security_level: SecurityLevel
    keymint_security_level: SecurityLevel
    attestation_version: int
    package_names: tuple[str, ...]
    verified_boot_state: str
    device_locked: bool
    os_patch_level: int | None
    root_subject: str

    def summary(self) -> dict:
        return {
            "type": "android_key_attestation",
            "security_level": self.security_level.label,
            "keymint_security_level": self.keymint_security_level.label,
            "attestation_version": self.attestation_version,
            "package_names": list(self.package_names),
            "verified_boot_state": self.verified_boot_state,
            "device_locked": self.device_locked,
            "os_patch_level": self.os_patch_level,
            "root": self.root_subject,
        }


def verify_android_attestation(
    chain_der: Sequence[bytes],
    signing_public_key_spki: bytes,
    challenge: bytes,
    policy: AndroidPolicy,
    *,
    now: datetime | None = None,
) -> AndroidAttestation:
    """Verify an Android Key Attestation certificate chain (leaf first).

    `signing_public_key_spki` is the SPKI DER of the key the app wants to
    enroll; the attested leaf must carry exactly that key.
    """
    now = now or utcnow()
    if not chain_der:
        raise EnrollmentError("attestation_missing", "Android attestation chain is empty")
    try:
        chain = [_AttCert.load(der) for der in chain_der]
    except Exception as exc:  # malformed DER from the client
        raise EnrollmentError("attestation_malformed", f"attestation certificate could not be parsed: {exc}") from exc

    roots = list(policy.trusted_roots) if policy.trusted_roots is not None else google_attestation_roots()
    root_keys = {spki_der(r): r for r in roots}

    top = chain[-1]
    anchor = root_keys.get(top.spki)
    if anchor is None:
        raise EnrollmentError("attestation_untrusted_root", "attestation chain does not end at a Google attestation root")
    # The device may carry an older copy of the root (Google re-issued its RSA
    # root with the same key), so the validity that counts is the anchor's.
    if not is_valid_at(anchor, now, skew=policy.clock_skew):
        raise EnrollmentError("attestation_cert_expired", "the Google attestation root is not valid now")
    for i, cert in enumerate(chain):
        is_top = i == len(chain) - 1
        if not is_top and not cert.valid_at(now, policy.clock_skew):
            raise EnrollmentError(
                "attestation_cert_expired", f"attestation certificate {i} ('{cert.subject}') is not valid now"
            )
        issuer_key = anchor.public_key() if is_top else chain[i + 1].public_key
        if not cert.signed_by(issuer_key):
            raise EnrollmentError("attestation_chain_invalid", f"attestation certificate {i} has a bad signature")

    if policy.revocation is not None:
        for cert in chain:
            status = policy.revocation.status_of_serial(cert.serial)
            if status in ("REVOKED", "SUSPENDED"):
                raise EnrollmentError("attestation_revoked", f"attestation certificate serial {cert.serial:x} is {status}")

    leaf = chain[0]
    if leaf.spki != signing_public_key_spki:
        raise EnrollmentError("attestation_key_mismatch", "the attested key is not the key being enrolled")
    if leaf.key_description is None:
        raise EnrollmentError("attestation_malformed", "leaf certificate has no key attestation extension")
    try:
        desc = parse_key_description(leaf.key_description)
    except (_der.DERError, ValueError) as exc:
        raise EnrollmentError("attestation_malformed", f"key attestation extension: {exc}") from exc

    if desc.attestation_challenge != challenge:
        raise EnrollmentError("challenge_mismatch", "attestation challenge does not match the issued challenge")
    if desc.attestation_security_level < policy.min_security_level:
        raise EnrollmentError(
            "attestation_security_level",
            f"attestation security level {desc.attestation_security_level.label} is below {policy.min_security_level.label}",
        )
    if desc.keymint_security_level < policy.min_security_level:
        raise EnrollmentError(
            "attestation_security_level",
            f"key security level {desc.keymint_security_level.label} is below {policy.min_security_level.label}",
        )

    hw = desc.hardware_enforced
    # Some StrongBox implementations omit TAG_EC_CURVE; the curve is then
    # established by the leaf key itself, which must equal the P-256 key enrolled.
    if hw.algorithm != KM_ALGORITHM_EC or (hw.ec_curve is not None and hw.ec_curve != KM_EC_CURVE_P_256):
        raise EnrollmentError("attestation_key_type", "attested key is not a hardware-enforced EC P-256 key")
    if KM_PURPOSE_SIGN not in hw.purposes:
        raise EnrollmentError("attestation_key_type", "attested key is not allowed to sign")
    if hw.origin != KM_ORIGIN_GENERATED:
        raise EnrollmentError("attestation_key_origin", "attested key was not generated inside the hardware")

    rot = hw.root_of_trust
    if rot is None:
        raise EnrollmentError("attestation_malformed", "no hardware-enforced root of trust")
    if policy.require_verified_boot and rot.verified_boot_state != VerifiedBootState.VERIFIED:
        raise EnrollmentError("device_integrity", f"verified boot state is {rot.verified_boot_state.name}")
    if policy.require_locked_bootloader and not rot.device_locked:
        raise EnrollmentError("device_integrity", "bootloader is unlocked")

    app = desc.lookup("application_id")
    if app is None:
        raise EnrollmentError("attestation_malformed", "no attestation application id")
    allowed_names = set(policy.package_names)
    if not allowed_names.intersection(app.package_names):
        raise EnrollmentError("app_mismatch", f"package {list(app.package_names)} is not allowed")
    allowed_digests = {bytes(d) for d in policy.signing_cert_sha256}
    if not allowed_digests.intersection(app.signature_digests):
        raise EnrollmentError("app_mismatch", "app signing certificate is not allowed")

    return AndroidAttestation(
        security_level=desc.attestation_security_level,
        keymint_security_level=desc.keymint_security_level,
        attestation_version=desc.attestation_version,
        package_names=app.package_names,
        verified_boot_state=rot.verified_boot_state.name,
        device_locked=rot.device_locked,
        os_patch_level=desc.lookup("os_patch_level"),
        root_subject=anchor.subject.rfc4514_string(),
    )
