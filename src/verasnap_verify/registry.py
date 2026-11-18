"""Trusted signing-key registry.

The insurer keeps one record per enrolled device signing key. The verifier
looks a proof's signing key up here: a key that is enrolled and active is
"known"; anything else makes the result Partially Verified at best, as in
the VeraSnap apps.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterable, Protocol

from ._crypto import b64decode, b64encode, key_fingerprint, load_p256_public_key, utcnow


@dataclass
class KeyRecord:
    fingerprint: str  # SHA-256 of the X9.63 public key, hex
    public_key_x963: str  # Base64
    platform: str  # "android" | "ios" | "manual"
    account_ref: str  # opaque reference chosen by the insurer (policy or customer id)
    security_level: str  # "STRONGBOX" | "TEE" | "SECURE_ENCLAVE" | "UNATTESTED"
    enrolled_at: str  # ISO 8601 UTC
    attestation: dict = field(default_factory=dict)
    status: str = "active"  # "active" | "revoked"
    revoked_at: str | None = None
    revoked_reason: str | None = None
    app_attest_sign_count: int | None = None  # iOS: last App Attest counter

    @property
    def active(self) -> bool:
        return self.status == "active"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KeyRecord":
        return cls(**data)

    @classmethod
    def manual(cls, public_key: bytes, account_ref: str, *, note: str = "") -> "KeyRecord":
        """Register a key without attestation (e.g. a VeraSnap app key checked in person).

        Results for such keys say the key is known, but the record shows it
        was not hardware-attested.
        """
        key = load_p256_public_key(public_key)
        from ._crypto import x963

        return cls(
            fingerprint=key_fingerprint(key),
            public_key_x963=b64encode(x963(key)),
            platform="manual",
            account_ref=account_ref,
            security_level="UNATTESTED",
            enrolled_at=utcnow().isoformat().replace("+00:00", "Z"),
            attestation={"type": "none", "note": note},
        )


class KeyRegistry(Protocol):
    def get(self, fingerprint: str) -> KeyRecord | None: ...

    def put(self, record: KeyRecord) -> None: ...

    def revoke(self, fingerprint: str, reason: str = "") -> bool: ...

    def list(self) -> Iterable[KeyRecord]: ...


class EnrollmentKeyRegistry(KeyRegistry, Protocol):
    def insert_if_absent(self, record: KeyRecord) -> bool:
        """Atomically insert a new fingerprint; return False without changing an existing record."""
        ...


class InMemoryKeyRegistry:
    def __init__(self, records: Iterable[KeyRecord] = ()):
        self._lock = threading.Lock()
        self._records: dict[str, KeyRecord] = {r.fingerprint.lower(): r for r in records}

    def get(self, fingerprint: str) -> KeyRecord | None:
        with self._lock:
            return self._records.get(fingerprint.lower())

    def put(self, record: KeyRecord) -> None:
        with self._lock:
            self._records[record.fingerprint.lower()] = record

    def insert_if_absent(self, record: KeyRecord) -> bool:
        with self._lock:
            fp = record.fingerprint.lower()
            if fp in self._records:
                return False
            self._records[fp] = record
            return True

    def revoke(self, fingerprint: str, reason: str = "") -> bool:
        with self._lock:
            rec = self._records.get(fingerprint.lower())
            if rec is None:
                return False
            rec.status = "revoked"
            rec.revoked_at = utcnow().isoformat().replace("+00:00", "Z")
            rec.revoked_reason = reason
            return True

    def list(self) -> list[KeyRecord]:
        with self._lock:
            return list(self._records.values())


class SqliteKeyRegistry:
    """Small persistent registry for PoCs. Production systems will use their own store."""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS signing_keys (fingerprint TEXT PRIMARY KEY, record TEXT NOT NULL)"
            )

    def get(self, fingerprint: str) -> KeyRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT record FROM signing_keys WHERE fingerprint = ?", (fingerprint.lower(),)
            ).fetchone()
        return KeyRecord.from_dict(json.loads(row[0])) if row else None

    def put(self, record: KeyRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO signing_keys (fingerprint, record) VALUES (?, ?)",
                (record.fingerprint.lower(), json.dumps(record.to_dict(), ensure_ascii=False)),
            )

    def insert_if_absent(self, record: KeyRecord) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO signing_keys (fingerprint, record) VALUES (?, ?) "
                "ON CONFLICT(fingerprint) DO NOTHING",
                (record.fingerprint.lower(), json.dumps(record.to_dict(), ensure_ascii=False)),
            )
            return cursor.rowcount == 1

    def revoke(self, fingerprint: str, reason: str = "") -> bool:
        rec = self.get(fingerprint)
        if rec is None:
            return False
        rec.status = "revoked"
        rec.revoked_at = utcnow().isoformat().replace("+00:00", "Z")
        rec.revoked_reason = reason
        self.put(rec)
        return True

    def list(self) -> list[KeyRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT record FROM signing_keys ORDER BY fingerprint").fetchall()
        return [KeyRecord.from_dict(json.loads(r[0])) for r in rows]

    def close(self) -> None:
        self._conn.close()


def record_public_key(record: KeyRecord):
    return load_p256_public_key(b64decode(record.public_key_x963, field="public_key_x963"))


def parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
