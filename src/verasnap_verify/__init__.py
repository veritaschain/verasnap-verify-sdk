"""VeraSnap Verify SDK.

Server-side verification of VeraSnap / CPP capture proofs, and enrollment of
device signing keys for insurers and other organisations that receive photos
as evidence.

    from verasnap_verify import Verifier, InMemoryKeyRegistry

    verifier = Verifier(registry=InMemoryKeyRegistry())
    result = verifier.verify(proof_bytes, media=photo_bytes)
    result.status   # ANCHOR_VERIFIED / PARTIALLY_VERIFIED / ... (see result.py)
    result.level    # "green" | "yellow" | "red"

Provenance is not truth: a green result says the proof meets VeraSnap's
verification criteria, not that the picture shows what really happened.
"""

__version__ = "0.1.0"

from .registry import InMemoryKeyRegistry, KeyRecord, KeyRegistry, SqliteKeyRegistry  # noqa: E402
from .result import Check, CheckStatus, Signer, Status, VerificationResult  # noqa: E402
from .tsa.rfc3161 import TrustStore, check_timestamp_token  # noqa: E402
from .verifier import ProofFormatError, Verifier, verify  # noqa: E402

__all__ = [
    "__version__",
    "Check",
    "CheckStatus",
    "InMemoryKeyRegistry",
    "KeyRecord",
    "KeyRegistry",
    "ProofFormatError",
    "Signer",
    "SqliteKeyRegistry",
    "Status",
    "TrustStore",
    "VerificationResult",
    "Verifier",
    "check_timestamp_token",
    "verify",
]
