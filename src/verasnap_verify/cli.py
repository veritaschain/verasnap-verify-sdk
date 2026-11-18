"""Command line interface.

    verasnap-verify verify proof.json --media photo.jpg [--registry keys.sqlite] [--json]
    verasnap-verify verify evidence_pack.zip
    verasnap-verify keys add --public-key <Base64 X9.63> --account policy-123 --registry keys.sqlite
    verasnap-verify keys list --registry keys.sqlite
    verasnap-verify keys revoke <fingerprint> --reason "device lost" --registry keys.sqlite

Exit codes for `verify`: 0 green, 1 yellow, 2 red, 3 usage or input error.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from . import __version__
from .registry import KeyRecord, SqliteKeyRegistry
from .result import CheckStatus
from .tsa.rfc3161 import TrustStore
from .verifier import ProofFormatError, Verifier

_MARK = {
    CheckStatus.PASSED: "PASS",
    CheckStatus.WARNING: "WARN",
    CheckStatus.FAILED: "FAIL",
    CheckStatus.SKIPPED: "SKIP",
    CheckStatus.INFO: "INFO",
}


def _cmd_verify(args) -> int:
    registry = SqliteKeyRegistry(args.registry) if args.registry else None
    trust = TrustStore.from_pem(Path(args.trust).read_bytes()) if args.trust else None
    verifier = Verifier(registry=registry, trust=trust, require_known_signer=not args.allow_unknown_signer)
    proof = Path(args.proof).read_bytes()
    media = Path(args.media).read_bytes() if args.media else None
    try:
        result = verifier.verify(proof, media)
    except (ProofFormatError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if args.json:
        print(result.to_json())
    else:
        print(f"{result.level.upper():6} {result.status.value}")
        print(result.summary)
        print()
        for c in result.checks:
            print(f"  [{_MARK[c.status]}] {c.id:18} {c.message}")
        if result.signer.fingerprint:
            print(f"\n  signer key {result.signer.short_fingerprint}  known={result.signer.known}  account={result.signer.account_ref}")
        if result.timestamp_time:
            print(f"  timestamp  {result.timestamp_time}  ({result.timestamp_authority})")
        if result.capture_time_device:
            print(f"  capture    {result.capture_time_device}  (device clock, not proven)")
    return {"green": 0, "yellow": 1}.get(result.level, 2)


def _cmd_keys(args) -> int:
    if not args.registry:
        print("error: --registry is required", file=sys.stderr)
        return 3
    reg = SqliteKeyRegistry(args.registry)
    if args.keys_cmd == "add":
        record = KeyRecord.manual(base64.b64decode(args.public_key), args.account, note=args.note or "")
        reg.put(record)
        print(record.fingerprint)
    elif args.keys_cmd == "list":
        for r in reg.list():
            print(f"{r.fingerprint}  {r.status:8} {r.platform:8} {r.security_level:22} {r.account_ref}")
    elif args.keys_cmd == "revoke":
        if not reg.revoke(args.fingerprint, args.reason or ""):
            print("error: no such key", file=sys.stderr)
            return 3
    elif args.keys_cmd == "show":
        r = reg.get(args.fingerprint)
        if r is None:
            print("error: no such key", file=sys.stderr)
            return 3
        print(json.dumps(r.to_dict(), indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verasnap-verify", description="Verify VeraSnap / CPP capture proofs.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify a proof JSON or Evidence Pack ZIP")
    v.add_argument("proof")
    v.add_argument("--media", help="the photo or video the proof is for")
    v.add_argument("--registry", help="SQLite key registry of enrolled device keys")
    v.add_argument("--trust", help="PEM bundle of TSA trust anchors (default: bundled roots)")
    v.add_argument("--json", action="store_true", help="print the full result as JSON")
    v.add_argument("--allow-unknown-signer", action="store_true", help="report unknown keys as info (demos only)")
    v.set_defaults(func=_cmd_verify)

    k = sub.add_parser("keys", help="manage the key registry")
    k.add_argument("--registry")
    ks = k.add_subparsers(dest="keys_cmd", required=True)
    ka = ks.add_parser("add", help="register a key without attestation")
    ka.add_argument("--public-key", required=True, help="Base64 X9.63 (as in a proof's public_key)")
    ka.add_argument("--account", required=True)
    ka.add_argument("--note")
    ks.add_parser("list")
    kr = ks.add_parser("revoke")
    kr.add_argument("fingerprint")
    kr.add_argument("--reason")
    kshow = ks.add_parser("show")
    kshow.add_argument("fingerprint")
    k.set_defaults(func=_cmd_keys)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
