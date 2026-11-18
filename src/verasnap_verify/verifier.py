"""Proof verification, ported from VeraSnap iOS `ProofVerificationService` 1.6
with the 1.6.1 rules (signer-key origin, capture time vs. TSA time, TSA time
only from a verified token, attestation shown as stated).

Differences from the app, all on the strict side, are marked "SDK:".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from . import __version__
from ._crypto import CryptoInputError, key_fingerprint, load_p256_public_key, utcnow
from .proof import jcs, merkle
from .proof.model import ModelError, project
from .registry import KeyRecord, KeyRegistry
from .result import (
    CHECK_ATTESTATION,
    CHECK_CAPTURE_TIME,
    CHECK_CHAIN_CONTEXT,
    CHECK_EVENT_HASH,
    CHECK_HUMAN_ATTESTATION,
    CHECK_IMPRINT,
    CHECK_MEDIA_HASH,
    CHECK_MERKLE,
    CHECK_PARSE,
    CHECK_SIGNATURE,
    CHECK_SIGNER_KEY,
    CHECK_TSA,
    CHECK_TSA_SIGNATURE,
    Check,
    CheckStatus,
    Signer,
    Status,
    VerificationResult,
    overall_status,
)
from .tsa.rfc3161 import UNTRUSTED_CHAIN, UNVERIFIABLE, VERIFIED, TimestampCheck, TrustStore, check_timestamp_token

MAX_PACK_BYTES = 512 * 1024 * 1024
MAX_PACK_MEMBERS = 64


class ProofFormatError(ValueError):
    pass


# ---------------------------------------------------------------- helpers


def _loads(text: str | bytes) -> Any:
    def _no_constants(name: str):
        raise ValueError(f"invalid JSON constant {name}")

    return json.loads(text, parse_constant=_no_constants)


def _strip_hash(value: str) -> str:
    return value.strip().lower().removeprefix("sha256:")


def _b64(value: str) -> bytes | None:
    text = "".join(value.split())
    if text.startswith("base64:"):
        text = text[len("base64:") :]
    if not text:
        return None
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    spec = "milliseconds" if dt.microsecond else "seconds"
    return dt.astimezone(timezone.utc).isoformat(timespec=spec).replace("+00:00", "Z")


def _fmt_delta(delta: timedelta) -> str:
    seconds = int(abs(delta.total_seconds()))
    if seconds >= 48 * 3600:
        d, rem = divmod(seconds, 86400)
        return f"{d} d {rem // 3600} h"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m} min"
    if m:
        return f"{m} min {s} s"
    return f"{s} s"


def _load_public_key(b64: str):
    data = _b64(b64)
    if data is None:
        raise CryptoInputError("public key: not valid Base64")
    if len(data) == 64:
        data = b"\x04" + data
    return load_p256_public_key(data)


def verify_es256_prehashed(public_key_b64: str, signature_value: str, digest: bytes) -> bool:
    """ES256 over a precomputed SHA-256 digest (the apps sign EventHash bytes directly)."""
    key = _load_public_key(public_key_b64)
    sig = _b64(signature_value.strip().removeprefix("es256:"))
    if sig is None:
        raise CryptoInputError("signature: not valid Base64")
    if len(sig) == 64:
        sig = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        key.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- shape checks (mirror iOS Codable)


def _req_str(obj: Mapping, key: str, path: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise ProofFormatError(f"{path}{key}: required string missing")
    return v


def _opt(obj: Mapping, key: str, types: tuple, path: str):
    v = obj.get(key)
    if v is None:
        return None
    if isinstance(v, bool) and bool not in types:
        raise ProofFormatError(f"{path}{key}: wrong type")
    if not isinstance(v, types):
        raise ProofFormatError(f"{path}{key}: wrong type")
    return v


def _check_chain_context(cc: Any) -> dict | None:
    if cc is None:
        return None
    if not isinstance(cc, dict):
        raise ProofFormatError("chain_context: expected object")
    for k in ("chain_id", "generated_at"):
        _req_str(cc, k, "chain_context.")
    for k in ("total_events", "active_events", "tombstone_count", "event_position"):
        if not isinstance(cc.get(k), int) or isinstance(cc.get(k), bool):
            raise ProofFormatError(f"chain_context.{k}: required integer missing")
    inv = cc.get("completeness_invariant")
    if not isinstance(inv, dict):
        raise ProofFormatError("chain_context.completeness_invariant: required object missing")
    return cc


def _is_shareable(doc: Mapping) -> bool:
    try:
        _req_str(doc, "proof_id", "")
        _req_str(doc, "proof_type", "")
        _req_str(doc, "proof_version", "")
        _req_str(doc, "event_hash", "")
        ev = doc.get("event")
        sig = doc.get("signature")
        if not isinstance(ev, dict) or not isinstance(sig, dict):
            return False
        for k in ("event_id", "event_type", "timestamp", "asset_hash"):
            _req_str(ev, k, "event.")
        _req_str(sig, "algo", "signature.")
        _req_str(sig, "value", "signature.")
        _opt(doc, "raw_event", (str,), "")
        _opt(doc, "public_key", (str,), "")
        _opt(doc, "attested", (bool,), "")
        tp = doc.get("timestamp_proof")
        if tp is not None:
            if not isinstance(tp, dict):
                return False
            for k in ("type", "issued_at", "token"):
                _req_str(tp, k, "timestamp_proof.")
            for k in ("merkle_root", "tsa_service", "anchor_digest", "digest_algorithm", "message_imprint"):
                _opt(tp, k, (str,), "timestamp_proof.")
            for k in ("tree_size", "merkle_index"):
                _opt(tp, k, (int,), "timestamp_proof.")
            mp = tp.get("merkle_proof")
            if mp is not None and (not isinstance(mp, list) or not all(isinstance(x, str) for x in mp)):
                return False
        _check_chain_context(doc.get("chain_context"))
        return True
    except ProofFormatError:
        return False


def _check_internal(doc: Mapping) -> None:
    for k in ("ProofVersion", "ProofType", "GeneratedAt", "GeneratedBy"):
        _req_str(doc, k, "")
    ev = doc.get("Event")
    if not isinstance(ev, dict):
        raise ProofFormatError("Event: required object missing")
    try:
        project(ev)
    except ModelError as exc:
        raise ProofFormatError(f"Event.{exc}") from exc
    ver = doc.get("Verification")
    if not isinstance(ver, dict):
        raise ProofFormatError("Verification: required object missing")
    _req_str(ver, "PublicKey", "Verification.")
    if not isinstance(doc.get("Metadata"), dict):
        raise ProofFormatError("Metadata: required object missing")
    anc = doc.get("Anchor")
    if anc is not None:
        if not isinstance(anc, dict):
            raise ProofFormatError("Anchor: expected object")
        for k in ("AnchorID", "AnchorType", "MerkleRoot"):
            _req_str(anc, k, "Anchor.")
        mp = anc.get("MerkleProof")
        if not isinstance(mp, list) or not all(isinstance(x, str) for x in mp):
            raise ProofFormatError("Anchor.MerkleProof: required list missing")
        if not isinstance(anc.get("MerkleIndex"), int) or isinstance(anc.get("MerkleIndex"), bool):
            raise ProofFormatError("Anchor.MerkleIndex: required integer missing")
        _opt(anc, "TreeSize", (int,), "Anchor.")
        for k in ("AnchorDigest", "AnchorDigestAlgorithm", "TSAResponse", "TSAMessageImprint", "TSATimestamp", "TSAService"):
            _opt(anc, k, (str,), "Anchor.")
    _check_chain_context(doc.get("ChainContext"))


# ---------------------------------------------------------------- verifier


@dataclass
class _State:
    checks: list[Check]
    tsa_fully_verified: bool = False
    tsa: TimestampCheck | None = None
    merkle_ok_full: bool = False  # inclusion proven (not omitted)
    signature_valid: bool = False
    signer_known: bool = False


class Verifier:
    """Verify VeraSnap proofs.

    registry: enrolled device keys; proofs signed with any other key are
        Partially Verified at best (as in the apps).
    trust: trust anchors for TSA certificates (default: bundled roots).
    require_known_signer: when False, the signer-key check is reported as
        "info" and does not affect the status. Use only for demos.
    """

    def __init__(
        self,
        *,
        registry: KeyRegistry | None = None,
        trust: TrustStore | None = None,
        require_known_signer: bool = True,
        max_anchor_delay: timedelta = timedelta(minutes=60),
        max_clock_ahead: timedelta = timedelta(minutes=5),
    ):
        self.registry = registry
        self.trust = trust if trust is not None else TrustStore.default()
        self.require_known_signer = require_known_signer
        self.max_anchor_delay = max_anchor_delay
        self.max_clock_ahead = max_clock_ahead

    # ------------------------------------------------------------ entry points

    def verify(self, proof: bytes | str | Mapping, media: bytes | None = None) -> VerificationResult:
        """Verify a proof (shareable JSON, internal proof.json, or an Evidence Pack ZIP)."""
        if isinstance(proof, (bytes, bytearray)) and bytes(proof[:4]) == b"PK\x03\x04":
            pack_proof, pack_media = self._read_pack(bytes(proof))
            return self.verify(pack_proof, media if media is not None else pack_media)
        try:
            doc = proof if isinstance(proof, Mapping) else _loads(proof)
            if not isinstance(doc, Mapping):
                raise ProofFormatError("top level is not a JSON object")
        except (ValueError, ProofFormatError) as exc:
            return self._error(f"JSON could not be parsed: {exc}")
        if _is_shareable(doc):
            return self._verify_shareable(doc, media)
        try:
            _check_internal(doc)
        except ProofFormatError as exc:
            return self._error(f"not a VeraSnap proof: {exc}")
        return self._verify_internal(doc, media)

    def verify_evidence_pack(self, data: bytes) -> VerificationResult:
        proof, media = self._read_pack(data)
        return self.verify(proof, media)

    # ------------------------------------------------------------ evidence pack

    @staticmethod
    def _read_pack(data: bytes) -> tuple[bytes, bytes | None]:
        if len(data) > MAX_PACK_BYTES:
            raise ProofFormatError("evidence pack is too large")
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise ProofFormatError(f"evidence pack is not a valid ZIP: {exc}") from exc
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_PACK_MEMBERS:
                raise ProofFormatError("evidence pack has too many files")
            names = {i.filename.rsplit("/", 1)[-1]: i for i in infos if not i.is_dir()}
            proof_info = names.get("proof.json")
            if proof_info is None:
                raise ProofFormatError("evidence pack has no proof.json")
            if sum(i.file_size for i in infos) > MAX_PACK_BYTES:
                raise ProofFormatError("evidence pack expands to more than the size limit")
            media_infos = [i for n, i in names.items() if n.startswith("media.")]
            try:
                media = zf.read(media_infos[0]) if media_infos else None
                return zf.read(proof_info), media
            except (zipfile.BadZipFile, OSError, ValueError) as exc:
                raise ProofFormatError(f"evidence pack could not be read: {exc}") from exc

    # ------------------------------------------------------------ shared steps

    def _error(self, message: str) -> VerificationResult:
        checks = [Check(CHECK_PARSE, CheckStatus.FAILED, "invalid", message)]
        return VerificationResult(
            status=Status.ERROR, checks=checks, summary=f"Not verified: {message}", sdk_version=__version__
        )

    def _signer_check(self, st: _State, public_key_b64: str | None, signer: Signer) -> None:
        if not st.signature_valid or not public_key_b64:
            return
        try:
            key = _load_public_key(public_key_b64)
        except CryptoInputError:
            return
        fp = key_fingerprint(key)
        signer.fingerprint = fp
        record: KeyRecord | None = self.registry.get(fp) if self.registry is not None else None
        status_if_unknown = CheckStatus.WARNING if self.require_known_signer else CheckStatus.INFO
        if record is None:
            st.checks.append(
                Check(
                    CHECK_SIGNER_KEY,
                    status_if_unknown,
                    "unknown",
                    f"Signed with a key that is not enrolled (key {fp[:16]}). The signature is valid, "
                    "but it does not show which device or app made it.",
                    {"fingerprint": fp},
                )
            )
            return
        signer.account_ref = record.account_ref
        signer.platform = record.platform
        signer.security_level = record.security_level
        signer.enrollment_status = record.status
        if not record.active:
            st.checks.append(
                Check(
                    CHECK_SIGNER_KEY,
                    status_if_unknown,
                    "revoked",
                    f"Signed with an enrolled key that was revoked at {record.revoked_at}"
                    + (f" ({record.revoked_reason})" if record.revoked_reason else "")
                    + ".",
                    {"fingerprint": fp, "revoked_at": record.revoked_at},
                )
            )
            return
        signer.known = True
        st.signer_known = True
        attested = record.security_level != "UNATTESTED"
        st.checks.append(
            Check(
                CHECK_SIGNER_KEY,
                CheckStatus.PASSED,
                "known" if attested else "known_unattested",
                f"Signed with an enrolled device key (account {record.account_ref}, {record.platform}, "
                f"{record.security_level})." + ("" if attested else " The key was registered without hardware attestation."),
                {"fingerprint": fp, "account_ref": record.account_ref},
            )
        )

    def _media_check(self, st: _State, media: bytes | None, expected: str | None, bound: bool, kind: str) -> bool:
        if media is None:
            st.checks.append(
                Check(CHECK_MEDIA_HASH, CheckStatus.SKIPPED, "not_provided", f"No {kind} was supplied, so the file itself was not checked.")
            )
            return False
        actual = hashlib.sha256(media).hexdigest()
        if expected is None or actual != _strip_hash(expected):
            st.checks.append(
                Check(
                    CHECK_MEDIA_HASH,
                    CheckStatus.FAILED,
                    "mismatch",
                    f"The {kind} does not match the proof (it was changed, re-encoded or replaced).",
                    {"expected": expected, "actual": "sha256:" + actual},
                )
            )
            return False
        if not bound:
            st.checks.append(
                Check(
                    CHECK_MEDIA_HASH,
                    CheckStatus.WARNING,
                    "not_bound",
                    f"The {kind} matches the hash written in the proof, but that value is not covered by the signature.",
                )
            )
            return False
        st.checks.append(Check(CHECK_MEDIA_HASH, CheckStatus.PASSED, "match", f"The {kind} matches the signed hash."))
        return True

    def _token_checks(self, st: _State, token: bytes, expected_hex: str, service: str | None) -> None:
        try:
            expected = bytes.fromhex(expected_hex) if expected_hex else b"\x00" * 33
        except ValueError:
            expected = b"\x00" * 33
        res = check_timestamp_token(token, expected_imprint=expected, trust=self.trust)
        st.tsa = res
        if res.message_imprint is not None:
            ok = res.message_imprint.hex() == expected_hex
            st.checks.append(
                Check(
                    CHECK_IMPRINT,
                    CheckStatus.PASSED if ok else CheckStatus.FAILED,
                    "match" if ok else "mismatch",
                    "The timestamp was issued for this proof's anchored digest."
                    if ok
                    else "The timestamp was issued for a different digest (token swapped or edited).",
                    {"expected": expected_hex, "actual": res.message_imprint.hex()},
                )
            )
        who = service or res.signer_subject or "TSA"
        if res.outcome == VERIFIED:
            st.tsa_fully_verified = True
            st.checks.append(
                Check(
                    CHECK_TSA_SIGNATURE,
                    CheckStatus.PASSED,
                    "valid",
                    f"Timestamp signature and certificate chain are valid ({res.signer_subject}).",
                    {"chain": list(res.chain_subjects), "anchor": res.anchor_subject},
                )
            )
            st.checks.append(
                Check(
                    CHECK_TSA,
                    CheckStatus.PASSED,
                    "verified",
                    f"RFC 3161 timestamp from {who} at {_iso(res.gen_time)}.",
                    {"gen_time": _iso(res.gen_time), "serial_number": res.serial_number, "policy": res.policy},
                )
            )
        elif res.outcome == UNTRUSTED_CHAIN:
            st.checks.append(
                Check(CHECK_TSA_SIGNATURE, CheckStatus.WARNING, "untrusted_chain", f"Timestamp signature is valid, but its certificate chain is not trusted: {res.reason}")
            )
            st.checks.append(
                Check(CHECK_TSA, CheckStatus.WARNING, "untrusted_chain", f"Timestamp from {who}; its time cannot be relied on because the TSA is not trusted.")
            )
        elif res.outcome == UNVERIFIABLE:
            st.checks.append(Check(CHECK_TSA, CheckStatus.WARNING, "unverifiable", f"Timestamp could not be verified: {res.reason}"))
        else:
            st.checks.append(Check(CHECK_TSA, CheckStatus.FAILED, "invalid", f"Timestamp is invalid: {res.reason}"))

    def _capture_time_check(self, st: _State, capture_time: Any, bound: bool) -> str | None:
        if not bound:
            st.checks.append(
                Check(CHECK_CAPTURE_TIME, CheckStatus.SKIPPED, "not_bound", "The capture time is not covered by the signature, so it was not compared.")
            )
            return None
        tsa_time = st.tsa.verified_gen_time if (st.tsa is not None and st.tsa_fully_verified and st.merkle_ok_full) else None
        if tsa_time is None:
            st.checks.append(
                Check(
                    CHECK_CAPTURE_TIME,
                    CheckStatus.SKIPPED,
                    "no_verified_timestamp",
                    "No fully verified timestamp, so the capture time could not be compared with an independent time.",
                )
            )
            return capture_time if isinstance(capture_time, str) else None
        cap = _parse_time(capture_time)
        if cap is None:
            st.checks.append(Check(CHECK_CAPTURE_TIME, CheckStatus.WARNING, "unreadable", "The recorded capture time could not be read."))
            return capture_time if isinstance(capture_time, str) else None
        details = {"capture_time_device": _iso(cap), "timestamp_time": _iso(tsa_time)}
        if cap - tsa_time > self.max_clock_ahead:
            st.checks.append(
                Check(
                    CHECK_CAPTURE_TIME,
                    CheckStatus.WARNING,
                    "capture_after_timestamp",
                    f"The recorded capture time is {_fmt_delta(cap - tsa_time)} after the timestamp; the device clock was wrong or changed.",
                    details,
                )
            )
        elif tsa_time - cap > self.max_anchor_delay:
            st.checks.append(
                Check(
                    CHECK_CAPTURE_TIME,
                    CheckStatus.WARNING,
                    "anchor_delayed",
                    f"The external timestamp was obtained {_fmt_delta(tsa_time - cap)} after the recorded capture time "
                    f"(more than {int(self.max_anchor_delay.total_seconds() // 60)} minutes), so the capture date and time "
                    "could not be independently confirmed. The photo existed no later than the timestamp.",
                    details,
                )
            )
        else:
            st.checks.append(
                Check(
                    CHECK_CAPTURE_TIME,
                    CheckStatus.PASSED,
                    "within_limit",
                    f"The timestamp was obtained {_fmt_delta(tsa_time - cap)} after the recorded capture time. "
                    "The capture time itself is the device clock's value.",
                    details,
                )
            )
        return _iso(cap)

    def _info_checks(self, st: _State, event: Mapping | None, chain_context: Mapping | None) -> None:
        ctx = (event or {}).get("CaptureContext") if isinstance(event, Mapping) else None
        ctx = ctx if isinstance(ctx, Mapping) else {}
        ka = ctx.get("KeyAttestation") if isinstance(ctx.get("KeyAttestation"), Mapping) else None
        if ka is not None:
            st.checks.append(
                Check(
                    CHECK_ATTESTATION,
                    CheckStatus.INFO,
                    "stated",
                    f"Attestation type {ka.get('AttestationType')!s} is stated in the proof but was not verified.",
                    {"attestation_type": ka.get("AttestationType")},
                )
            )
        ha = ctx.get("HumanAttestation") if isinstance(ctx.get("HumanAttestation"), Mapping) else None
        if ha is not None:
            counted = st.signer_known
            st.checks.append(
                Check(
                    CHECK_HUMAN_ATTESTATION,
                    CheckStatus.INFO,
                    "recorded" if ha.get("Verified") is True else "recorded_failed",
                    f"A biometric check ({ha.get('Method')}) is recorded with result {ha.get('Verified')}."
                    + ("" if counted else " It is not counted because the signing key is not enrolled.")
                    + " It does not identify the photographer.",
                    {"verified": ha.get("Verified"), "method": ha.get("Method"), "counted": counted},
                )
            )
        if chain_context is not None:
            tomb = chain_context.get("tombstone_count", 0)
            st.checks.append(
                Check(
                    CHECK_CHAIN_CONTEXT,
                    CheckStatus.INFO,
                    "deletions_recorded" if tomb else "present",
                    (f"The capture history records {tomb} deleted item(s). " if tomb else "")
                    + "Chain context is not covered by the signature and can be edited; treat it as a hint.",
                    {"total_events": chain_context.get("total_events"), "tombstone_count": tomb},
                )
            )

    def _summarize(self, status: Status, checks: list[Check], media_kind: str, media_verified: bool) -> str:
        signer = next((c for c in checks if c.id == CHECK_SIGNER_KEY), None)
        signer_ok = signer is None or signer.status is not CheckStatus.WARNING
        if status is Status.ANCHOR_VERIFIED:
            first = (
                f"the {media_kind} has not changed since it was signed"
                if media_verified
                else f"the proof is intact; the {media_kind} itself was not checked because it was not supplied"
            )
            return (
                f"Meets VeraSnap's verification criteria: {first}, and the timestamp was obtained within "
                f"{int(self.max_anchor_delay.total_seconds() // 60)} minutes of the recorded capture time. "
                "The capture time is the device clock's value; the content of the picture is not judged."
            )
        if status is Status.PARTIALLY_VERIFIED:
            # Only say the file is intact when the signer is known; an unknown
            # signer may have signed an edited or generated file.
            lead = f"{media_kind.capitalize()} integrity confirmed. " if media_verified and signer_ok else ""
            reasons = " ".join(c.message for c in checks if c.status is CheckStatus.WARNING)
            return f"Partially verified. {lead}{reasons}"
        if status is Status.ANCHOR_PENDING:
            return "No verified external timestamp: the signature is valid, but when the proof existed is not independently confirmed."
        reasons = " ".join(c.message for c in checks if c.status is CheckStatus.FAILED)
        return f"Not verified. {reasons}"

    # ------------------------------------------------------------ shareable

    def _verify_shareable(self, doc: Mapping, media: bytes | None) -> VerificationResult:
        st = _State(checks=[])
        version = doc["proof_version"]
        event = doc["event"]
        st.checks.append(Check(CHECK_PARSE, CheckStatus.PASSED, "shareable", f"Shareable proof, version {version}."))

        event_hash_field: str = doc["event_hash"]
        computed: str | None = None
        signed_raw: dict | None = None
        signed_asset_hash: str | None = None
        raw_b64 = doc.get("raw_event")
        eh_status, eh_code, eh_msg = CheckStatus.FAILED, "mismatch", "EventHash does not match the event."
        if raw_b64 is not None:
            raw = _b64(raw_b64)
            parsed = None
            if raw is not None:
                try:
                    parsed = _loads(raw)
                except ValueError:
                    parsed = None
            if raw is None:
                eh_code, eh_msg = "raw_event_invalid", "raw_event is not valid Base64."
            elif not isinstance(parsed, dict):
                eh_code, eh_msg = "raw_event_invalid", "raw_event is not a JSON object."
            else:
                raw_hash = hashlib.sha256(raw).hexdigest()
                if raw_hash == _strip_hash(event_hash_field):
                    computed = raw_hash
                else:
                    try:
                        computed = hashlib.sha256(jcs.canonicalize(parsed)).hexdigest()
                    except jcs.CanonicalizationError as exc:
                        eh_code, eh_msg = "raw_event_invalid", f"raw_event could not be canonicalized: {exc}"
                if computed is not None and computed == _strip_hash(event_hash_field):
                    asset = parsed.get("Asset") if isinstance(parsed.get("Asset"), dict) else None
                    r_asset = asset.get("AssetHash") if asset else None
                    r_id, r_ts = parsed.get("EventID"), parsed.get("Timestamp")
                    if isinstance(r_asset, str) and isinstance(r_id, str) and isinstance(r_ts, str):
                        if r_asset == event["asset_hash"] and r_id == event["event_id"] and r_ts == event["timestamp"]:
                            eh_status, eh_code, eh_msg = CheckStatus.PASSED, "match", "EventHash matches the signed event."
                            signed_asset_hash, signed_raw = r_asset, parsed
                        else:
                            eh_code = "raw_event_inconsistent"
                            eh_msg = "EventHash matches raw_event, but the event section was edited (asset hash, ID or time differ)."
                    else:
                        eh_status, eh_code, eh_msg = CheckStatus.PASSED, "match", "EventHash matches the signed event."
                        signed_asset_hash = r_asset if isinstance(r_asset, str) else None
                        signed_raw = parsed
        else:
            if event_hash_field.startswith("sha256:"):
                eh_status, eh_code = CheckStatus.WARNING, "raw_event_missing"
                eh_msg = "raw_event is missing, so the EventHash could not be recomputed (format checked only)."
            else:
                eh_code, eh_msg = "format_invalid", "EventHash has an invalid format."
        st.checks.append(Check(CHECK_EVENT_HASH, eh_status, eh_code, eh_msg))

        # Signature over the recomputed hash (never the value written in the JSON, when raw_event exists)
        public_key = doc.get("public_key") or None
        hash_for_sig = computed or _strip_hash(event_hash_field)
        if public_key:
            try:
                ok = verify_es256_prehashed(public_key, doc["signature"]["value"], bytes.fromhex(hash_for_sig))
                code, msg = ("valid", "ES256 signature is valid.") if ok else ("invalid", "ES256 signature is not valid.")
            except (CryptoInputError, ValueError) as exc:
                ok, code, msg = False, "malformed", f"Signature could not be checked: {exc}"
        else:
            ok, code, msg = False, "no_public_key", "No public key in the proof, so the signature cannot be checked."
        st.signature_valid = ok
        st.checks.append(Check(CHECK_SIGNATURE, CheckStatus.PASSED if ok else CheckStatus.FAILED, code, msg))

        signer = Signer(public_key=public_key)
        self._signer_check(st, public_key, signer)

        asset_type = (event.get("asset_type") or "").upper()
        kind = "video" if asset_type == "VIDEO" else "photo"
        media_verified = self._media_check(st, media, signed_asset_hash or event["asset_hash"], signed_asset_hash is not None, kind)

        tp = doc.get("timestamp_proof")
        if tp is not None:
            eh_hex = computed or _strip_hash(event_hash_field)
            merkle_root = tp.get("merkle_root")
            if merkle_root:
                tree_size = tp.get("tree_size") or 1
                omitted = False
                if tree_size == 1:
                    ok_m, legacy = merkle.verify_single(eh_hex, merkle_root)
                else:
                    proof_path, index = tp.get("merkle_proof"), tp.get("merkle_index")
                    if proof_path and index is not None:
                        ok_m = merkle.verify_inclusion(eh_hex, proof_path, int(index), merkle_root)
                    else:
                        ok_m, omitted = True, True
                if not ok_m:
                    st.checks.append(Check(CHECK_MERKLE, CheckStatus.FAILED, "mismatch", "The event is not included in the anchored Merkle root."))
                elif omitted:
                    st.checks.append(
                        Check(CHECK_MERKLE, CheckStatus.WARNING, "proof_omitted", f"The Merkle proof is omitted (tree size {tree_size}), so inclusion in the anchored batch could not be confirmed.")
                    )
                else:
                    st.merkle_ok_full = True
                    st.checks.append(Check(CHECK_MERKLE, CheckStatus.PASSED, "match", f"The event is included in the anchored Merkle root (tree size {tree_size})."))
            else:
                st.merkle_ok_full = True  # digest is derived from the EventHash directly below

            token = _b64(tp.get("token") or "")
            if token is None:
                st.checks.append(Check(CHECK_TSA, CheckStatus.FAILED, "invalid", "The timestamp token is empty or not valid Base64."))
            else:
                if merkle_root:
                    root_hex = _strip_hash(merkle_root)
                    anchor_digest = tp.get("anchor_digest")
                    if anchor_digest and anchor_digest.lower() != root_hex:
                        st.checks.append(
                            Check(CHECK_TSA, CheckStatus.FAILED, "anchor_digest_mismatch", "anchor_digest differs from merkle_root (possible timestamp replay).")
                        )
                        expected_hex = ""
                    else:
                        expected_hex = root_hex
                else:
                    try:
                        expected_hex = hashlib.sha256(bytes.fromhex(eh_hex)).hexdigest() if len(eh_hex) == 64 else ""
                    except ValueError:
                        expected_hex = ""
                self._token_checks(st, token, expected_hex, tp.get("tsa_service") or tp.get("type"))
        else:
            if _version_at_least(version, 1.1):
                st.checks.append(
                    Check(CHECK_TSA, CheckStatus.FAILED, "missing", f"timestamp_proof is missing (required for version {version}); it may have been stripped.")
                )

        capture_bound = signed_raw is not None
        capture_raw = signed_raw.get("Timestamp") if signed_raw else event.get("timestamp")
        capture_iso = self._capture_time_check(st, capture_raw, capture_bound)
        cc = doc.get("chain_context")
        self._info_checks(st, signed_raw, cc)

        status = overall_status(st.checks, timestamp_fully_verified=(tp is not None and st.tsa_fully_verified))
        return VerificationResult(
            status=status,
            checks=st.checks,
            summary=self._summarize(status, st.checks, kind, media_verified),
            format="shareable",
            proof_version=version,
            proof_id=doc.get("proof_id"),
            event_id=event.get("event_id"),
            capture_time_device=capture_iso if capture_bound else None,
            timestamp_time=_iso(st.tsa.verified_gen_time) if st.tsa and st.tsa_fully_verified else None,
            timestamp_authority=(st.tsa.signer_subject if st.tsa and st.tsa_fully_verified else None),
            media_verified=media_verified,
            signer=signer,
            chain_context=dict(cc) if cc else None,
            sdk_version=__version__,
        )

    # ------------------------------------------------------------ internal

    def _verify_internal(self, doc: Mapping, media: bytes | None) -> VerificationResult:
        st = _State(checks=[])
        version = doc["ProofVersion"]
        event = dict(doc["Event"])
        st.checks.append(Check(CHECK_PARSE, CheckStatus.PASSED, "internal", f"Internal proof.json, version {version}."))

        body = {k: v for k, v in event.items() if k not in ("EventHash", "Signature")}
        field_hash = _strip_hash(event["EventHash"])
        candidates: list[tuple[str, str, list[str]]] = []
        try:
            candidates.append(("exact", hashlib.sha256(jcs.canonicalize(body)).hexdigest(), []))
        except jcs.CanonicalizationError:
            pass
        projected, dropped = project(event)
        projected_body = {k: v for k, v in projected.items() if k not in ("EventHash", "Signature")}
        candidates.append(("ios_model", hashlib.sha256(jcs.canonicalize(projected_body)).hexdigest(), dropped))

        match = next((c for c in candidates if c[1] == field_hash), None)
        if match is None:
            st.checks.append(Check(CHECK_EVENT_HASH, CheckStatus.FAILED, "mismatch", "EventHash does not match the event (the event was edited)."))
        elif match[0] == "exact" or not match[2]:
            st.checks.append(Check(CHECK_EVENT_HASH, CheckStatus.PASSED, "match", "EventHash matches the event."))
        else:
            # SDK: the iOS app passes this silently.
            st.checks.append(
                Check(
                    CHECK_EVENT_HASH,
                    CheckStatus.WARNING,
                    "unsigned_fields",
                    "EventHash matches only after dropping fields that are not covered by the signature: " + ", ".join(match[2]) + ".",
                    {"unsigned_fields": match[2]},
                )
            )

        public_key = doc["Verification"]["PublicKey"]
        ok = False
        code, msg = "invalid", "ES256 signature is not valid."
        try:
            for _, h, _ in candidates:
                if verify_es256_prehashed(public_key, event["Signature"], bytes.fromhex(h)):
                    ok, code, msg = True, "valid", "ES256 signature is valid."
                    break
        except (CryptoInputError, ValueError) as exc:
            ok, code, msg = False, "malformed", f"Signature could not be checked: {exc}"
        st.signature_valid = ok
        st.checks.append(Check(CHECK_SIGNATURE, CheckStatus.PASSED if ok else CheckStatus.FAILED, code, msg))

        signer = Signer(public_key=public_key)
        self._signer_check(st, public_key, signer)

        asset = event["Asset"]
        kind = "video" if str(asset.get("AssetType", "")).upper() == "VIDEO" else "photo"
        media_verified = self._media_check(st, media, asset.get("AssetHash"), True, kind)

        anchor = doc.get("Anchor")
        if anchor is not None:
            eh_hex = field_hash
            root_hex = _strip_hash(anchor["MerkleRoot"])
            tree_size = anchor.get("TreeSize") or 1
            if tree_size == 1:
                ok_m, _legacy = merkle.verify_single(eh_hex, root_hex)
                reason = "Single-leaf Merkle root does not equal SHA-256(EventHash)."
            else:
                ok_m = merkle.verify_inclusion(eh_hex, anchor["MerkleProof"], anchor["MerkleIndex"], root_hex)
                reason = "Merkle proof verification failed."
            digest = anchor.get("AnchorDigest")
            if ok_m and digest is not None and digest.lower() != root_hex:
                ok_m, reason = False, "AnchorDigest differs from MerkleRoot."
            token_text = anchor.get("TSAResponse")
            if not ok_m:
                st.checks.append(Check(CHECK_MERKLE, CheckStatus.FAILED, "mismatch", reason))
            elif not token_text:
                st.checks.append(Check(CHECK_TSA, CheckStatus.WARNING, "missing_token", "The anchor has no TSAResponse, so the timestamp cannot be verified."))
            else:
                token = _b64(token_text)
                if token is None:
                    st.checks.append(Check(CHECK_MERKLE, CheckStatus.FAILED, "invalid_token", "TSAResponse is not valid Base64."))
                else:
                    st.merkle_ok_full = True
                    st.checks.append(Check(CHECK_MERKLE, CheckStatus.PASSED, "match", f"The event is included in the anchored Merkle root (tree size {tree_size})."))
                    expected_hex = (digest or root_hex).lower()
                    self._token_checks(st, token, expected_hex, anchor.get("TSAService"))
        elif _version_at_least(version, 1.1):
            st.checks.append(Check(CHECK_TSA, CheckStatus.FAILED, "missing", f"Anchor is missing (required for version {version}); it may have been stripped."))

        capture_iso = self._capture_time_check(st, event.get("Timestamp"), True)
        cc = doc.get("ChainContext")
        self._info_checks(st, event, cc)

        status = overall_status(st.checks, timestamp_fully_verified=(anchor is not None and st.tsa_fully_verified))
        return VerificationResult(
            status=status,
            checks=st.checks,
            summary=self._summarize(status, st.checks, kind, media_verified),
            format="internal",
            proof_version=version,
            proof_id=event.get("EventID"),
            event_id=event.get("EventID"),
            capture_time_device=capture_iso,
            timestamp_time=_iso(st.tsa.verified_gen_time) if st.tsa and st.tsa_fully_verified else None,
            timestamp_authority=(st.tsa.signer_subject if st.tsa and st.tsa_fully_verified else None),
            media_verified=media_verified,
            signer=signer,
            chain_context=dict(cc) if cc else None,
            sdk_version=__version__,
        )


def _version_at_least(version: str, minimum: float) -> bool:
    try:
        return float(version) >= minimum
    except (TypeError, ValueError):
        return False


def verify(proof: bytes | str | Mapping, media: bytes | None = None, **kwargs) -> VerificationResult:
    """Convenience wrapper: `Verifier(**kwargs).verify(proof, media)`."""
    return Verifier(**kwargs).verify(proof, media)
