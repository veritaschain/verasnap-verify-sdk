#!/usr/bin/env python3
"""Route a claim photo using an account reference from the insurer's claim record.

    python3 examples/verify_claim_photo.py proof.json photo.jpg keys.sqlite --expected-account policy-123
"""

import argparse
from pathlib import Path

from verasnap_verify import CheckStatus, SqliteKeyRegistry, VerificationResult, Verifier


def claim_route(result: VerificationResult, expected_account: str | None) -> str:
    if result.level == "red":
        return "refer: review the failed proof checks"

    signer = result.check("signer_key")
    if (
        result.level == "green"
        and result.media_verified
        and signer is not None
        and signer.status is CheckStatus.PASSED
        and signer.code == "known"
        and expected_account
        and result.signer.account_ref == expected_account
    ):
        return "fast track: photo matches, attested key registered to expected account"
    return "normal review: check the photo, signer enrollment, account and proof details"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", type=Path)
    parser.add_argument("photo", type=Path)
    parser.add_argument("registry", nargs="?")
    parser.add_argument("--expected-account", help="account reference from the insurer's authenticated claim record")
    args = parser.parse_args()
    registry = SqliteKeyRegistry(args.registry) if args.registry else None
    result = Verifier(registry=registry).verify(args.proof.read_bytes(), args.photo.read_bytes())
    print(result.status.value, "-", claim_route(result, args.expected_account))
    for check in result.checks:
        if check.status in (CheckStatus.FAILED, CheckStatus.WARNING):
            print(f"  {check.status.value}: {check.id} ({check.code}) {check.message}")


if __name__ == "__main__":
    main()
