"""Insurance-fraud scenarios (tests/fixtures/scenarios, made by tools/make_fixtures.py).

Each scenario names the expected overall status and which checks must fail,
warn or be skipped. Every other check must pass or be informational.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verasnap_verify import CheckStatus, InMemoryKeyRegistry, KeyRecord, TrustStore, Verifier
from verasnap_verify._crypto import load_pem_bundle

HERE = Path(__file__).parent / "fixtures" / "scenarios"
MANIFEST = json.loads((HERE / "manifest.json").read_text())


def _registry(kind: str) -> InMemoryKeyRegistry:
    reg = InMemoryKeyRegistry()
    if kind == "empty":
        return reg
    keys = MANIFEST["keys"]
    import base64

    reg.put(KeyRecord.manual(base64.b64decode(keys["device_enrolled"]), "policy-0001"))
    revoked = KeyRecord.manual(base64.b64decode(keys["device_revoked"]), "policy-0002")
    reg.put(revoked)
    reg.revoke(revoked.fingerprint, "device reported stolen")
    return reg


def _trust(kind: str) -> TrustStore:
    default = TrustStore.default()
    if kind == "sectigo_only":
        return TrustStore([a for a in default.anchors if "Sectigo" in a.subject.rfc4514_string()])
    return default


@pytest.mark.parametrize("scenario", MANIFEST["scenarios"], ids=[s["id"] for s in MANIFEST["scenarios"]])
def test_scenario(scenario):
    proof = (HERE / scenario["proof"]).read_bytes()
    media = (HERE / "media" / scenario["media"]).read_bytes() if scenario["media"] else None
    verifier = Verifier(registry=_registry(scenario["registry"]), trust=_trust(scenario["trust"]))
    result = verifier.verify(proof, media)
    expect = scenario["expect"]
    by_status = {s: sorted({c.id for c in result.checks if c.status is s}) for s in CheckStatus}
    context = f"{scenario['id']} {scenario['title']}\n{result.to_json()}"

    assert result.status.value == expect["status"], context
    assert by_status[CheckStatus.FAILED] == sorted(set(expect.get("failed", []))), context
    assert by_status[CheckStatus.WARNING] == sorted(set(expect.get("warning", []))), context
    if "skipped" in expect:
        assert set(expect["skipped"]) <= set(by_status[CheckStatus.SKIPPED]), context
    for check_id, code in expect.get("codes", {}).items():
        assert result.check(check_id) is not None and result.check(check_id).code == code, context
    if "media_verified" in expect:
        assert result.media_verified is expect["media_verified"], context
    # The verified TSA time is reported only when the timestamp was fully verified.
    if result.timestamp_time is not None:
        assert result.check("timestamp").status is CheckStatus.PASSED, context


def test_green_requires_no_warnings():
    for s in MANIFEST["scenarios"]:
        if s["expect"]["status"] == "ANCHOR_VERIFIED":
            assert not s["expect"].get("warning"), s["id"]
