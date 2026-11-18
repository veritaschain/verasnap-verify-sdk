#!/usr/bin/env python3
"""Generate the insurance-fraud scenario fixtures (tests/fixtures/scenarios).

Proofs are built the way the VeraSnap apps build them (iOS 1.6 CPPEventBuilder
and StorageService): the event dictionary is canonicalized with the iOS
JSONCanonicalizer rules, hashed with SHA-256, signed over the digest with
ES256 (DER), batched into a Merkle tree, and the root is timestamped by a
real RFC 3161 TSA. Run once with network access; tests then run offline.

Usage: python3 tools/make_fixtures.py [--out tests/fixtures/scenarios]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import os
import random
import shutil
import sys
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asn1crypto import algos, cms, tsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verasnap_verify.proof import jcs, merkle  # noqa: E402

TSA_AIMODA = "https://rfc3161.ai.moda"
TSA_SECTIGO = "http://timestamp.sectigo.com"
TSA_DIGICERT = "http://timestamp.digicert.com"

rng = random.Random(20261118)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fake_jpeg(seed: int, size: int = 4096) -> bytes:
    r = random.Random(seed)
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(r.getrandbits(8) for _ in range(size)) + b"\xff\xd9"


def x963(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_or_make_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return key


def uuid7ish() -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def make_event(key, media: bytes, capture: datetime, *, chain_id: str, prev: str = "GENESIS", video: bool = False,
               ios_full: bool = True) -> dict:
    """Event dict as the app encodes it (before EventHash/Signature are set)."""
    pub = x963(key)
    ev = {
        "EventID": uuid7ish(),
        "ChainID": chain_id,
        "PrevHash": prev,
        "Timestamp": iso(capture),
        "EventType": "INGEST",
        "HashAlgo": "SHA256",
        "SignAlgo": "ES256",
        "Asset": {
            "AssetID": "urn:cpp:asset:verasnap:" + uuid7ish(),
            "AssetType": "VIDEO" if video else "IMAGE",
            "AssetHash": "sha256:" + hashlib.sha256(media).hexdigest(),
            "AssetName": "VID_0001.mov" if video else "IMG_0001.jpg",
            "AssetSize": len(media),
            "MimeType": "video/quicktime" if video else "image/jpeg",
        },
        "CaptureContext": {
            "DeviceID": "sha256:" + hashlib.sha256(b"device-" + pub).hexdigest(),
            "DeviceModel": "iPhone 16 Pro" if ios_full else "Pixel 9 Pro",
            "OSVersion": "iOS 26.1" if ios_full else "Android 16",
            "AppVersion": "VeraSnap/1.6.1",
            "KeyAttestation": {
                "AttestationType": "APPLE_APP_ATTEST" if ios_full else "ANDROID_STRONGBOX",
                "AttestationData": b64(os.urandom(48)),
                "KeyID": "sha256:" + hashlib.sha256(pub).hexdigest(),
            },
            "HumanAttestation": {
                "Verified": True,
                "Method": "FaceID" if ios_full else "BIOMETRIC_STRONG",
                "VerifiedAt": iso(capture - timedelta(milliseconds=850)),
                "CaptureOffsetMs": 850,
                "SessionNonce": uuid7ish(),
            },
        },
        "SensorData": {
            "GPS": {"LatitudeHash": "sha256:" + "ab" * 32, "LongitudeHash": "sha256:" + "cd" * 32, "Altitude": 4.5, "Accuracy": 1},
            "Accelerometer": [0.012, -0.981, 0.0, 1.0],
            "Compass": 271.25,
            "Barometer": {"PressureHPa": 1013.2, "RelativeAltitudeM": 0, "Timestamp": iso(capture)},
            "TimeConsistency": {
                "DeviceTimestamp": iso(capture),
                "NTPTimestamp": iso(capture + timedelta(milliseconds=12)),
                "OffsetMs": -12.5,
                "IsConsistent": True,
                "NTPServer": "time.apple.com",
                "VerificationMethod": "NTP",
            },
        },
        "CameraSettings": {"FocalLength": 6.86, "Aperture": 1.78, "ISO": 64, "ExposureTime": 0.008333333333333333, "FlashMode": "off"},
    }
    if video:
        ev["Asset"]["VideoMetadata"] = {"Duration": 12.5, "Resolution": {"Width": 1920, "Height": 1080}, "FrameRate": 30, "Codec": "hevc", "HasAudio": True}
    if ios_full:
        # Fields the generator writes but the iOS 1.6 verification model does not know.
        ev["CaptureContext"]["CaptureAssertion"] = {
            "KeyID": b64(os.urandom(32)),
            "Assertion": b64(os.urandom(64)),
            "ClientDataHash": hashlib.sha256(os.urandom(8)).hexdigest(),
            "IsSimulator": False,
        }
    return ev


def seal(event: dict, key) -> dict:
    body = {k: v for k, v in event.items() if k not in ("EventHash", "Signature")}
    canonical = jcs.canonicalize(body)
    digest = hashlib.sha256(canonical).digest()
    sig = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    sealed = dict(event)
    sealed["EventHash"] = "sha256:" + digest.hex()
    sealed["Signature"] = "es256:" + b64(sig)
    sealed["_raw"] = canonical  # kept out of the JSON output
    return sealed


def timestamp(root_hex: str, url: str) -> bytes:
    req = tsp.TimeStampReq(
        {
            "version": 1,
            "message_imprint": {"hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}), "hashed_message": bytes.fromhex(root_hex)},
            "nonce": rng.getrandbits(63),
            "cert_req": True,
        }
    ).dump()
    http = urllib.request.Request(url, data=req, headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(http, timeout=30) as resp:
        body = resp.read()
    parsed = tsp.TimeStampResp.load(body)
    if parsed["status"]["status"].native not in ("granted", "granted_with_mods"):
        raise RuntimeError(f"TSA {url} refused: {parsed['status']['status'].native}")
    return parsed["time_stamp_token"].dump()


def gen_time(token: bytes) -> datetime:
    ci = cms.ContentInfo.load(token)
    return tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)["gen_time"].native


def anchor(events: list[dict], url: str) -> dict:
    tree = merkle.build([e["EventHash"] for e in events])
    token = timestamp(tree.root, url)
    return {"tree": tree, "token": token, "gen_time": gen_time(token), "url": url}


def shareable(event: dict, key, anc: dict | None, index: int = 0, *, chain_context: dict | None = None) -> dict:
    ev = copy.deepcopy(event)
    doc = {
        "proof_id": ev["EventID"],
        "proof_type": "CPP_INGEST_PROOF",
        "proof_version": "1.2",
        "event": {
            "event_id": ev["EventID"],
            "event_type": ev["EventType"],
            "timestamp": ev["Timestamp"],
            "asset_hash": ev["Asset"]["AssetHash"],
            "asset_type": ev["Asset"]["AssetType"],
            "asset_name": ev["Asset"]["AssetName"],
            "camera_settings": ev.get("CameraSettings"),
            "sensor_data": ev.get("SensorData"),
        },
        "raw_event": b64(ev["_raw"]),
        "event_hash": ev["EventHash"],
        "signature": {"algo": "ES256", "value": ev["Signature"]},
        "public_key": b64(x963(key)),
        "attested": True,
    }
    if anc is not None:
        tree = anc["tree"]
        doc["timestamp_proof"] = {
            "type": "RFC3161",
            "issued_at": iso(anc["gen_time"]),
            "token": b64(anc["token"]),
            "merkle_root": "sha256:" + tree.root,
            "tsa_service": anc["url"],
            "tree_size": tree.tree_size,
            "anchor_digest": tree.root,
            "digest_algorithm": "sha-256",
            "message_imprint": tree.root,
            "merkle_index": index,
            "merkle_proof": tree.proofs[index],
            "leaf_hash_method": "SHA256(EventHash)",
        }
    if chain_context is not None:
        doc["chain_context"] = chain_context
    return doc


def internal(event: dict, key, anc: dict | None, index: int = 0) -> dict:
    ev = copy.deepcopy({k: v for k, v in event.items() if k != "_raw"})
    doc = {
        "ProofVersion": "1.2",
        "ProofType": "CPP_INGEST_PROOF",
        "GeneratedAt": iso(datetime.now(timezone.utc)),
        "GeneratedBy": "VeraSnap/1.6.1",
        "Event": ev,
        "Verification": {"PublicKey": b64(x963(key))},
        "Metadata": {"OriginalFilename": ev["Asset"]["AssetName"], "OriginalSize": ev["Asset"]["AssetSize"]},
    }
    if anc is not None:
        tree = anc["tree"]
        doc["Anchor"] = {
            "AnchorID": uuid7ish(),
            "AnchorType": "RFC3161",
            "MerkleRoot": "sha256:" + tree.root,
            "MerkleProof": tree.proofs[index],
            "MerkleIndex": index,
            "TreeSize": tree.tree_size,
            "AnchorDigest": tree.root,
            "AnchorDigestAlgorithm": "sha-256",
            "LeafHashMethod": "SHA256(EventHash)",
            "TSAResponse": b64(anc["token"]),
            "TSAMessageImprint": tree.root,
            "TSATimestamp": iso(anc["gen_time"]),
            "TSAService": anc["url"],
        }
    return doc


def chain_ctx(chain_id: str, events: list[dict], position: int, tombstones: int = 0) -> dict:
    acc = bytes(32)
    for e in events:
        h = hashlib.sha256(bytes.fromhex(e["EventHash"].removeprefix("sha256:"))).digest()
        acc = bytes(a ^ b for a, b in zip(acc, h))
    return {
        "chain_id": chain_id,
        "total_events": len(events) + tombstones,
        "active_events": len(events),
        "tombstone_count": tombstones,
        "event_position": position,
        "completeness_invariant": {
            "expected_count": len(events) + tombstones,
            "hash_sum": acc.hex(),
            "first_timestamp": events[0]["Timestamp"],
            "last_timestamp": events[-1]["Timestamp"],
            "algorithm": "XOR-SHA256",
            "version": "1.0",
        },
        "generated_at": iso(datetime.now(timezone.utc)),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "tests" / "fixtures" / "scenarios"))
    args = ap.parse_args()
    out = Path(args.out)
    keys_dir = out / "keys"
    if out.exists():
        for p in out.iterdir():
            if p.name != "keys":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
    keys_dir.mkdir(parents=True, exist_ok=True)

    d1 = load_or_make_key(keys_dir / "device_enrolled.pem")
    d2 = load_or_make_key(keys_dir / "device_revoked.pem")
    atk = load_or_make_key(keys_dir / "attacker.pem")

    now = datetime.now(timezone.utc)
    photo = fake_jpeg(1)
    photo_edited = bytearray(photo)
    photo_edited[2000] ^= 0x01
    photo_edited = bytes(photo_edited)
    photo_recompressed = fake_jpeg(2, 3900)
    photo_other = fake_jpeg(3)
    photo_ai = fake_jpeg(4)
    video = fake_jpeg(5, 9000)

    media = {
        "photo.jpg": photo,
        "photo_edited.jpg": photo_edited,
        "photo_recompressed.jpg": photo_recompressed,
        "photo_other.jpg": photo_other,
        "photo_ai_generated.jpg": photo_ai,
        "video.mov": video,
    }
    (out / "media").mkdir(parents=True, exist_ok=True)
    for name, data in media.items():
        (out / "media" / name).write_bytes(data)

    print("timestamping …", file=sys.stderr)
    e_main = seal(make_event(d1, photo, now - timedelta(seconds=90), chain_id="chain-main"), d1)
    a_main = anchor([e_main], TSA_AIMODA)
    e_other = seal(make_event(d1, photo_other, now - timedelta(seconds=60), chain_id="chain-main", prev=e_main["EventHash"]), d1)
    a_other = anchor([e_other], TSA_AIMODA)
    e_forged = seal(make_event(atk, photo_ai, now - timedelta(seconds=45), chain_id="chain-x"), atk)
    a_forged = anchor([e_forged], TSA_AIMODA)
    e_back = seal(make_event(d1, photo, now - timedelta(days=30), chain_id="chain-main"), d1)
    a_back = anchor([e_back], TSA_AIMODA)
    e_ahead = seal(make_event(d1, photo, now + timedelta(minutes=20), chain_id="chain-main"), d1)
    a_ahead = anchor([e_ahead], TSA_AIMODA)
    batch_media = [fake_jpeg(100 + i) for i in range(5)]
    batch = [seal(make_event(d1, m, now - timedelta(minutes=20 - i), chain_id="chain-batch"), d1) for i, m in enumerate(batch_media)]
    a_batch = anchor(batch, TSA_DIGICERT)
    for i, m in enumerate(batch_media):
        (out / "media" / f"batch_{i}.jpg").write_bytes(m)
    e_sect = seal(make_event(d1, photo, now - timedelta(seconds=30), chain_id="chain-main"), d1)
    a_sect = anchor([e_sect], TSA_SECTIGO)
    e_video = seal(make_event(d1, video, now - timedelta(seconds=20), chain_id="chain-main", video=True), d1)
    a_video = anchor([e_video], TSA_AIMODA)
    e_rev = seal(make_event(d2, photo, now - timedelta(seconds=10), chain_id="chain-rev"), d2)
    a_rev = anchor([e_rev], TSA_AIMODA)
    e_android = seal(make_event(d1, photo, now - timedelta(seconds=5), chain_id="chain-android", ios_full=False), d1)
    for k in ("CaptureAssertion",):
        e_android["CaptureContext"].pop(k, None)
    a_android = anchor([e_android], TSA_AIMODA)

    scenarios: list[dict] = []

    def add(sid: str, title: str, proof: dict | bytes, media_file: str | None, expect: dict, *, registry: str = "default",
            trust: str = "default", ext: str = "json"):
        d = out / sid
        d.mkdir(parents=True, exist_ok=True)
        name = f"proof.{ext}"
        if isinstance(proof, bytes):
            (d / name).write_bytes(proof)
        else:
            (d / name).write_text(json.dumps(proof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        scenarios.append({"id": sid, "title": title, "proof": f"{sid}/{name}", "media": media_file, "registry": registry, "trust": trust, "expect": expect})

    base = shareable(e_main, d1, a_main)
    add("S01", "Genuine capture, enrolled key, photo supplied", base, "photo.jpg", {"status": "ANCHOR_VERIFIED"})
    add("S02", "Genuine capture, key not enrolled", base, "photo.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["signer_key"]}, registry="empty")
    add("S03", "Photo edited after capture (one bit)", base, "photo_edited.jpg", {"status": "HASH_MISMATCH", "failed": ["media_hash"]})
    add("S04", "Photo re-compressed", base, "photo_recompressed.jpg", {"status": "HASH_MISMATCH", "failed": ["media_hash"]})
    add("S05", "Photo swapped for another real photo", base, "photo_other.jpg", {"status": "HASH_MISMATCH", "failed": ["media_hash"]})
    add("S06", "Forged proof: AI image, attacker's own key, real TSA token", shareable(e_forged, atk, a_forged), "photo_ai_generated.jpg",
        {"status": "PARTIALLY_VERIFIED", "warning": ["signer_key"]})
    s = copy.deepcopy(base); s["public_key"] = b64(x963(atk))
    add("S07", "Public key replaced with the attacker's", s, "photo.jpg", {"status": "SIGNATURE_INVALID", "failed": ["signature"]})
    s = copy.deepcopy(base); s["event"]["asset_hash"] = "sha256:" + hashlib.sha256(photo_ai).hexdigest()
    add("S08", "Event section edited to point at another photo", s, "photo_ai_generated.jpg", {"status": "HASH_MISMATCH", "failed": ["event_hash"], "warning": ["media_hash"],
         "codes": {"event_hash": "raw_event_inconsistent", "media_hash": "not_bound"}})
    s = copy.deepcopy(base); s.pop("raw_event")
    add("S09", "raw_event removed", s, "photo.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["event_hash", "media_hash"]})
    s = copy.deepcopy(base)
    raw = json.loads(base64.b64decode(s["raw_event"])); raw["Asset"]["AssetHash"] = "sha256:" + hashlib.sha256(photo_ai).hexdigest()
    s["raw_event"] = b64(jcs.canonicalize(raw))
    add("S10", "raw_event edited to match an AI image", s, "photo_ai_generated.jpg", {"status": "SIGNATURE_INVALID", "failed": ["event_hash", "signature", "media_hash", "merkle_inclusion"]})
    add("S11", "Backdated: capture time 30 days before the timestamp", shareable(e_back, d1, a_back), "photo.jpg",
        {"status": "PARTIALLY_VERIFIED", "warning": ["capture_time"], "codes": {"capture_time": "anchor_delayed"}})
    add("S12", "Device clock ahead of the timestamp by 20 minutes", shareable(e_ahead, d1, a_ahead), "photo.jpg",
        {"status": "PARTIALLY_VERIFIED", "warning": ["capture_time"], "codes": {"capture_time": "capture_after_timestamp"}})
    s = copy.deepcopy(base); s.pop("timestamp_proof")
    add("S13", "Timestamp stripped", s, "photo.jpg", {"status": "ERROR", "failed": ["timestamp"]})
    s = copy.deepcopy(base); s["timestamp_proof"]["token"] = b64(a_other["token"])
    add("S14", "Timestamp token swapped from another proof", s, "photo.jpg", {"status": "ERROR", "failed": ["message_imprint", "timestamp"]})
    s = copy.deepcopy(base); s["timestamp_proof"]["anchor_digest"] = a_other["tree"].root
    add("S15", "anchor_digest edited", s, "photo.jpg", {"status": "ERROR", "failed": ["timestamp", "message_imprint"],
        "codes": {"timestamp": "anchor_digest_mismatch"}})
    add("S16", "Batch anchor (5 events), Merkle proof for event 3", shareable(batch[3], d1, a_batch, 3), "batch_3.jpg", {"status": "ANCHOR_VERIFIED"})
    s = shareable(batch[3], d1, a_batch, 3); s["timestamp_proof"].pop("merkle_proof"); s["timestamp_proof"].pop("merkle_index")
    add("S17", "Batch anchor with the Merkle proof omitted", s, "batch_3.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["merkle_inclusion"]})
    add("S18", "TSA root not trusted by the verifier", base, "photo.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["tsa_signature", "timestamp"]}, trust="sectigo_only")
    add("S19", "Sectigo timestamp", shareable(e_sect, d1, a_sect), "photo.jpg", {"status": "ANCHOR_VERIFIED"})
    add("S20", "Photo not supplied", base, None, {"status": "ANCHOR_VERIFIED", "skipped": ["media_hash"], "media_verified": False})
    s = shareable(e_main, d1, a_main, chain_context=chain_ctx("chain-main", [e_main, e_other], 1, tombstones=2))
    add("S21", "Chain context records deletions (unsigned, informational)", s, "photo.jpg",
        {"status": "ANCHOR_VERIFIED", "codes": {"chain_context": "deletions_recorded"}})
    s = copy.deepcopy(base); tok = bytearray(a_main["token"]); tok[-10] ^= 0xFF; s["timestamp_proof"]["token"] = b64(bytes(tok))
    add("S22", "Timestamp token corrupted", s, "photo.jpg", {"status": "ERROR", "failed": ["timestamp"]})

    add("S23", "Internal proof.json (iOS event with fields outside the iOS 1.6 verify model)", internal(e_main, d1, a_main), "photo.jpg",
        {"status": "ANCHOR_VERIFIED", "codes": {"event_hash": "match"}})
    s = internal(e_android, d1, a_android); s["Event"]["CaptureContext"]["Note"] = "added after signing"
    add("S24", "Internal proof.json with a field added after signing", s, "photo.jpg",
        {"status": "PARTIALLY_VERIFIED", "warning": ["event_hash"], "codes": {"event_hash": "unsigned_fields"}})
    s = internal(e_main, d1, a_main); s["Event"]["CaptureContext"]["DeviceModel"] = "iPhone 17 Pro"
    add("S25", "Internal proof.json with an event field edited", s, "photo.jpg", {"status": "SIGNATURE_INVALID", "failed": ["event_hash", "signature"]})
    s = internal(e_main, d1, a_main); s.pop("Anchor")
    add("S26", "Internal proof.json with the anchor stripped", s, "photo.jpg", {"status": "ERROR", "failed": ["timestamp"]})
    s = internal(e_main, d1, a_main); s["Anchor"].pop("TSAResponse")
    add("S27", "Internal proof.json without the TSA token", s, "photo.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["timestamp"]})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("media.jpg", photo)
        zf.writestr("proof.json", json.dumps(internal(e_main, d1, a_main), indent=2))
    add("S28", "Evidence Pack ZIP (media.jpg + proof.json)", buf.getvalue(), None, {"status": "ANCHOR_VERIFIED", "media_verified": True}, ext="zip")
    add("S29", "Video capture", shareable(e_video, d1, a_video), "video.mov", {"status": "ANCHOR_VERIFIED"})
    add("S30", "Key revoked by the insurer", shareable(e_rev, d2, a_rev), "photo.jpg", {"status": "PARTIALLY_VERIFIED", "warning": ["signer_key"], "codes": {"signer_key": "revoked"}})
    add("S31", "Android-style internal proof.json", internal(e_android, d1, a_android), "photo.jpg", {"status": "ANCHOR_VERIFIED"})

    manifest = {
        "generated_at": iso(now),
        "generator": "tools/make_fixtures.py",
        "keys": {
            "device_enrolled": b64(x963(d1)),
            "device_revoked": b64(x963(d2)),
            "attacker": b64(x963(atk)),
        },
        "scenarios": scenarios,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(scenarios)} scenarios to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
