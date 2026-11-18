"""RFC 3161 time-stamp token verification (with RFC 5816 ESSCertIDv2).

The checks and their order follow `TSATokenVerifier` in VeraSnap iOS 1.6:

1. TimeStampResp (PKIStatus granted) or bare TimeStampToken;
2. CMS SignedData with eContentType id-ct-TSTInfo;
3. messageImprint equals the anchored digest, with SHA-256 (when expected);
4. exactly one SignerInfo with signed attributes, none duplicated;
5. content-type attribute is TSTInfo and message-digest matches TSTInfo;
6. the signer certificate is in the token (else "unverifiable");
7. SigningCertificate / SigningCertificateV2 identifies that certificate;
8. its only extended key usage is id-kp-timeStamping, marked critical;
9. the signature over the signed attributes verifies;
10. a chain to a trust anchor is valid at genTime (else "untrusted chain").

Revocation (CRL/OCSP) is not checked, as in the apps.

Outcomes: ``verified``, ``untrusted_chain``, ``unverifiable``, ``invalid``.
genTime is a usable time only when the outcome is ``verified``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Iterable

from asn1crypto import cms, tsp
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from .. import _der
from .._crypto import ChainError, build_path, load_certificate, load_pem_bundle

_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

VERIFIED = "verified"
UNTRUSTED_CHAIN = "untrusted_chain"
UNVERIFIABLE = "unverifiable"
INVALID = "invalid"


class TimestampError(Exception):
    def __init__(self, outcome: str, message: str):
        super().__init__(f"{outcome}: {message}")
        self.outcome = outcome
        self.message = message


@dataclass
class TrustStore:
    """Trust anchors (and optional extra intermediates) for TSA certificates."""

    anchors: list[x509.Certificate]
    intermediates: list[x509.Certificate] = field(default_factory=list)

    @classmethod
    def from_pem(cls, data: bytes) -> "TrustStore":
        return cls(load_pem_bundle(data))

    @classmethod
    def default(cls) -> "TrustStore":
        """Roots of common TSAs, including those the VeraSnap apps use (see data/README.md)."""
        pem = resources.files("verasnap_verify.data").joinpath("tsa_roots.pem").read_bytes()
        return cls.from_pem(pem)


@dataclass
class TimestampCheck:
    outcome: str
    reason: str | None = None
    message_imprint: bytes | None = None
    imprint_algorithm: str | None = None
    gen_time: datetime | None = None  # parsed even when not verified; trust only if outcome == verified
    serial_number: int | None = None
    policy: str | None = None
    signer_subject: str | None = None
    chain_subjects: tuple[str, ...] = ()
    anchor_subject: str | None = None

    @property
    def verified(self) -> bool:
        return self.outcome == VERIFIED

    @property
    def verified_gen_time(self) -> datetime | None:
        return self.gen_time if self.verified else None


def _digest(name: str, data: bytes) -> bytes:
    algo = _HASHES.get(name)
    if algo is None:
        raise TimestampError(UNVERIFIABLE, f"unsupported digest algorithm {name}")
    h = hashes.Hash(algo())
    h.update(data)
    return h.finalize()


def _load_token(token: bytes) -> cms.ContentInfo:
    """Accept a bare TimeStampToken (ContentInfo) or a full TimeStampResp."""
    outer = _der.parse_one(token)
    children = outer.children()
    if not children:
        raise TimestampError(INVALID, "empty SEQUENCE")
    if children[0].is_universal(_der.TAG_SEQUENCE):  # TimeStampResp starts with PKIStatusInfo
        resp = tsp.TimeStampResp.load(token)
        status = resp["status"]["status"].native
        if status not in ("granted", "granted_with_mods"):
            raise TimestampError(INVALID, f"TSA rejected the request (PKIStatus={status})")
        if len(children) < 2:
            raise TimestampError(INVALID, "timeStampToken missing")
        content_info = resp["time_stamp_token"]
    else:
        content_info = cms.ContentInfo.load(token)
    if content_info["content_type"].native != "signed_data":
        raise TimestampError(INVALID, "ContentInfo is not SignedData")
    return content_info


def _find_signer(sid: cms.SignerIdentifier, certs: Iterable[a_x509.Certificate]) -> a_x509.Certificate | None:
    if sid.name == "issuer_and_serial_number":
        want_issuer = sid.chosen["issuer"]
        want_serial = sid.chosen["serial_number"].native
        for c in certs:
            if c.serial_number == want_serial and c.issuer == want_issuer:
                return c
    elif sid.name == "subject_key_identifier":
        want = sid.chosen.native
        for c in certs:
            if c.key_identifier == want:
                return c
    return None


def _verify_signature(cert: x509.Certificate, signer_info: cms.SignerInfo, signed_data: bytes) -> None:
    key = cert.public_key()
    sig_algo = signer_info["signature_algorithm"]
    signature = signer_info["signature"].native
    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    algo_name = sig_algo["algorithm"].native
    try:
        if algo_name == "rsassa_pss":
            params = sig_algo["parameters"]
            hash_name = params["hash_algorithm"]["algorithm"].native
            mgf_hash = params["mask_gen_algorithm"]["parameters"]["algorithm"].native
            if not isinstance(key, rsa.RSAPublicKey) or hash_name not in _HASHES or mgf_hash not in _HASHES:
                raise TimestampError(UNVERIFIABLE, "signature algorithm not supported for this key")
            key.verify(
                signature,
                signed_data,
                padding.PSS(mgf=padding.MGF1(_HASHES[mgf_hash]()), salt_length=params["salt_length"].native),
                _HASHES[hash_name](),
            )
            return
        try:
            hash_name = sig_algo.hash_algo
        except (ValueError, KeyError):
            hash_name = digest_name
        if hash_name not in _HASHES:
            raise TimestampError(UNVERIFIABLE, f"unsupported signature algorithm {algo_name}")
        if isinstance(key, rsa.RSAPublicKey) and "ecdsa" not in algo_name:
            key.verify(signature, signed_data, padding.PKCS1v15(), _HASHES[hash_name]())
        elif isinstance(key, ec.EllipticCurvePublicKey) and "rsa" not in algo_name:
            key.verify(signature, signed_data, ec.ECDSA(_HASHES[hash_name]()))
        else:
            raise TimestampError(UNVERIFIABLE, "signature algorithm not supported for this key")
    except InvalidSignature as exc:
        raise TimestampError(INVALID, "TSA signature is invalid") from exc
    except ValueError as exc:
        raise TimestampError(INVALID, f"TSA signature is invalid ({exc})") from exc


def _run(
    token: bytes,
    expected_imprint: bytes | None,
    trust: TrustStore | None,
    extra_certificates: Iterable[x509.Certificate],
    out: TimestampCheck,
) -> None:
    try:
        content_info = _load_token(token)
        signed = content_info["content"]
        encap = signed["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise TimestampError(INVALID, "eContentType is not id-ct-TSTInfo")
        if encap["content"] is None or encap["content"].contents is None:
            raise TimestampError(INVALID, "eContent missing")
        tst_bytes = encap["content"].contents
        tst_info = tsp.TSTInfo.load(tst_bytes)
        imprint = tst_info["message_imprint"]
        out.imprint_algorithm = imprint["hash_algorithm"]["algorithm"].native
        out.message_imprint = imprint["hashed_message"].native
        gen_time = tst_info["gen_time"].native
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)
        out.gen_time = gen_time.astimezone(timezone.utc)
        out.serial_number = tst_info["serial_number"].native
        out.policy = tst_info["policy"].dotted
        signer_infos = signed["signer_infos"]
        certificates = signed["certificates"]
    except TimestampError:
        raise
    except Exception as exc:  # asn1crypto/_der raise many types on malformed input
        raise TimestampError(INVALID, f"malformed timestamp token: {exc}") from exc

    if expected_imprint is not None:
        if out.message_imprint != expected_imprint:
            raise TimestampError(INVALID, "messageImprint does not match the anchored digest")
        if out.imprint_algorithm != "sha256":
            raise TimestampError(INVALID, "messageImprint algorithm is not SHA-256")

    if len(signer_infos) != 1:
        raise TimestampError(INVALID, f"expected exactly one SignerInfo, found {len(signer_infos)}")
    si = signer_infos[0]
    signed_attrs = si["signed_attrs"]
    if not signed_attrs or len(signed_attrs) == 0:
        raise TimestampError(INVALID, "signedAttrs missing")
    digest_name = si["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise TimestampError(UNVERIFIABLE, f"unsupported digest algorithm {digest_name}")

    attrs: dict = {}
    for a in signed_attrs:
        name = a["type"].native
        if name in attrs:
            raise TimestampError(INVALID, f"duplicate signed attribute {name}")
        attrs[name] = a["values"]
    if "content_type" not in attrs or attrs["content_type"][0].native != "tst_info":
        raise TimestampError(INVALID, "contentType attribute is not id-ct-TSTInfo")
    if "message_digest" not in attrs:
        raise TimestampError(INVALID, "messageDigest attribute missing")
    if attrs["message_digest"][0].native != _digest(digest_name, tst_bytes):
        raise TimestampError(INVALID, "messageDigest does not match TSTInfo (token was modified)")

    embedded = [c.chosen for c in (certificates or []) if c.name == "certificate"]
    extra_list = list(extra_certificates)
    extras_a = [a_x509.Certificate.load(c.public_bytes(Encoding.DER)) for c in extra_list]
    if not embedded and not extras_a:
        raise TimestampError(UNVERIFIABLE, "TSA certificate not included in the token")
    signer_a = _find_signer(si["sid"], embedded + extras_a)
    if signer_a is None:
        raise TimestampError(UNVERIFIABLE, "signer certificate not found in the token")
    signer_der = signer_a.dump()
    try:
        signer = load_certificate(signer_der)
    except Exception as exc:
        raise TimestampError(INVALID, "signer certificate could not be decoded") from exc
    out.signer_subject = signer.subject.rfc4514_string()

    if "signing_certificate" not in attrs and "signing_certificate_v2" not in attrs:
        raise TimestampError(INVALID, "signingCertificate attribute missing")
    if "signing_certificate" in attrs:
        ids = attrs["signing_certificate"][0]["certs"]
        if not ids or ids[0]["cert_hash"].native != hashlib.sha1(signer_der).digest():
            raise TimestampError(INVALID, "ESSCertID does not match the signer certificate")
    if "signing_certificate_v2" in attrs:
        ids = attrs["signing_certificate_v2"][0]["certs"]
        if not ids:
            raise TimestampError(INVALID, "signingCertificateV2 value")
        first = ids[0]
        algo = first["hash_algorithm"]["algorithm"].native if first["hash_algorithm"] else "sha256"
        if first["cert_hash"].native != _digest(algo, signer_der):
            raise TimestampError(INVALID, "ESSCertIDv2 does not match the signer certificate")

    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        eku = None
    if eku is None or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING] or not eku.critical:
        raise TimestampError(INVALID, "signer certificate is not a dedicated time-stamping certificate (EKU)")

    signed_attrs_der = b"\x31" + signed_attrs.dump()[1:]
    _verify_signature(signer, si, signed_attrs_der)

    if trust is None:
        out.outcome = UNTRUSTED_CHAIN
        out.reason = "certificate chain was not checked"
        return
    pool = [load_certificate(c.dump()) for c in embedded] + extra_list + list(trust.intermediates)
    try:
        chain = build_path(signer, pool, trust.anchors, at=out.gen_time)
    except ChainError as exc:
        out.outcome = UNTRUSTED_CHAIN
        out.reason = str(exc)
        return
    out.chain_subjects = tuple(c.subject.rfc4514_string() for c in chain.path)
    out.anchor_subject = chain.anchor.subject.rfc4514_string()
    out.outcome = VERIFIED


def check_timestamp_token(
    token: bytes,
    *,
    expected_imprint: bytes | None,
    trust: TrustStore | None,
    extra_certificates: Iterable[x509.Certificate] = (),
) -> TimestampCheck:
    """Check a DER token (or TimeStampResp). Never raises; see `TimestampCheck.outcome`.

    Pass `trust=None` to skip the chain check (the outcome is then at best
    ``untrusted_chain``).
    """
    out = TimestampCheck(outcome=INVALID)
    try:
        _run(token, expected_imprint, trust, extra_certificates, out)
    except TimestampError as exc:
        out.outcome = exc.outcome
        out.reason = exc.message
    return out


def verify_timestamp_token(
    token: bytes,
    *,
    expected_imprint: bytes | None,
    trust: TrustStore,
    extra_certificates: Iterable[x509.Certificate] = (),
) -> TimestampCheck:
    """Like `check_timestamp_token`, but raises `TimestampError` unless fully verified."""
    result = check_timestamp_token(
        token, expected_imprint=expected_imprint, trust=trust, extra_certificates=extra_certificates
    )
    if not result.verified:
        raise TimestampError(result.outcome, result.reason or result.outcome)
    return result
