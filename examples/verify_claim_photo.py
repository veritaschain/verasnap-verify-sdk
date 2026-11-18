#!/usr/bin/env python3
"""Minimal example: verify a claim photo and decide how to route the claim.

    python3 examples/verify_claim_photo.py proof.json photo.jpg keys.sqlite
"""

import sys
from pathlib import Path

from verasnap_verify import SqliteKeyRegistry, Verifier

proof = Path(sys.argv[1]).read_bytes()
photo = Path(sys.argv[2]).read_bytes()
registry = SqliteKeyRegistry(sys.argv[3]) if len(sys.argv) > 3 else None

result = Verifier(registry=registry).verify(proof, photo)

# One possible routing rule. The decision is the insurer's; the SDK only reports facts.
if result.level == "green":
    route = "fast track: sealed at capture, enrolled device, photo unchanged"
elif result.level == "yellow":
    route = "normal review: see warnings (e.g. unknown signing key, late timestamp)"
else:
    route = "refer: proof does not match the photo or was altered"

print(result.status.value, "-", route)
for check in result.checks:
    if check.status.value in ("failed", "warning"):
        print(f"  {check.status.value}: {check.id} ({check.code}) {check.message}")
