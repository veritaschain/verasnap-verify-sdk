from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from attest_helpers import NOW, AndroidFixture, AppleFixture
from verasnap_verify import InMemoryKeyRegistry, KeyRecord, SqliteKeyRegistry, Verifier
from verasnap_verify._crypto import b64encode, spki_der, x963
from verasnap_verify.enroll import (
    AndroidPolicy,
    ApplePolicy,
    Enroller,
    EnrollmentError,
    EnrollmentPolicy,
    RevocationList,
    SecurityLevel,
    enrollment_client_data,
    proof_of_possession_message,
)
from verasnap_verify.enroll.android import google_attestation_roots, parse_key_description, verify_android_attestation
from verasnap_verify.enroll.apple import apple_app_attest_root, verify_app_attest, verify_app_attest_assertion

DIGEST = hashlib.sha256(b"release-cert").digest()


@pytest.fixture
def android():
    return AndroidFixture()


@pytest.fixture
def apple():
    return AppleFixture()


def android_policy(fx: AndroidFixture, **kw) -> AndroidPolicy:
    return AndroidPolicy(package_names=["org.veritaschain.verasnap"], signing_cert_sha256=[DIGEST], trusted_roots=[fx.root], **kw)


def apple_policy(fx: AppleFixture, **kw) -> ApplePolicy:
    return ApplePolicy(app_ids=[fx.app_id], trusted_roots=[fx.root], **kw)


# ---------------------------------------------------------------- bundled roots


def test_bundled_google_roots():
    roots = google_attestation_roots()
    assert len(roots) == 2
    subjects = [r.subject.rfc4514_string() for r in roots]
    assert any("f92009e853b6b045" in s for s in subjects)
    assert any("Key Attestation CA1" in s for s in subjects)


def test_bundled_apple_root_fingerprint():
    root = apple_app_attest_root()
    assert root.fingerprint(hashes.SHA256()).hex().upper() == "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932"


# ---------------------------------------------------------------- Android


def test_android_ok(android):
    ch = b"c" * 32
    res = verify_android_attestation(android.chain(ch), spki_der(android.signing_key.public_key()), ch, android_policy(android))
    assert res.security_level is SecurityLevel.STRONGBOX
    assert res.package_names == ("org.veritaschain.verasnap",)
    assert res.verified_boot_state == "VERIFIED"


@pytest.mark.parametrize(
    "kwargs,policy_kw,code",
    [
        ({"package": "com.evil.app"}, {}, "app_mismatch"),
        ({"signing_digest": b"\x00" * 32}, {}, "app_mismatch"),
        ({"security_level": 0}, {}, "attestation_security_level"),
        ({"security_level": 1}, {"min_security_level": SecurityLevel.STRONGBOX}, "attestation_security_level"),
        ({"verified_boot_state": 2}, {}, "device_integrity"),
        ({"device_locked": False}, {}, "device_integrity"),
        ({"origin": 2}, {}, "attestation_key_origin"),
        ({"curve": 3}, {}, "attestation_key_type"),
        ({"purposes": (3,)}, {}, "attestation_key_type"),
    ],
)
def test_android_policy_failures(android, kwargs, policy_kw, code):
    ch = b"c" * 32
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(android.chain(ch, **kwargs), spki_der(android.signing_key.public_key()), ch, android_policy(android, **policy_kw))
    assert exc.value.code == code


def test_android_tee_allowed_by_default(android):
    ch = b"c" * 32
    res = verify_android_attestation(android.chain(ch, security_level=1), spki_der(android.signing_key.public_key()), ch, android_policy(android))
    assert res.security_level is SecurityLevel.TRUSTED_ENVIRONMENT


def test_android_wrong_challenge(android):
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(android.chain(b"a" * 32), spki_der(android.signing_key.public_key()), b"b" * 32, android_policy(android))
    assert exc.value.code == "challenge_mismatch"


def test_android_key_mismatch(android):
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(android.chain(b"c" * 32), spki_der(other.public_key()), b"c" * 32, android_policy(android))
    assert exc.value.code == "attestation_key_mismatch"


def test_android_untrusted_root(android):
    other = AndroidFixture()
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(android.chain(b"c" * 32), spki_der(android.signing_key.public_key()), b"c" * 32, android_policy(other))
    assert exc.value.code == "attestation_untrusted_root"


def test_android_default_roots_reject_test_chain(android):
    policy = AndroidPolicy(package_names=["org.veritaschain.verasnap"], signing_cert_sha256=[DIGEST])
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(android.chain(b"c" * 32), spki_der(android.signing_key.public_key()), b"c" * 32, policy)
    assert exc.value.code == "attestation_untrusted_root"


def test_android_tampered_chain(android):
    chain = android.chain(b"c" * 32)
    leaf = bytearray(chain[0])
    leaf[-5] ^= 0x01
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation([bytes(leaf)] + chain[1:], spki_der(android.signing_key.public_key()), b"c" * 32, android_policy(android))
    assert exc.value.code in ("attestation_chain_invalid", "attestation_malformed")


def test_android_revoked(android):
    from cryptography import x509

    chain = android.chain(b"c" * 32)
    inter = x509.load_der_x509_certificate(chain[1])
    rl = RevocationList.from_json(json.dumps({"entries": {format(inter.serial_number, "x"): {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}))
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(chain, spki_der(android.signing_key.public_key()), b"c" * 32, android_policy(android, revocation=rl))
    assert exc.value.code == "attestation_revoked"


def test_parse_key_description_skips_unknown_tags(android):
    from attest_helpers import key_description

    desc = parse_key_description(key_description(b"x" * 16))
    assert 724 in desc.hardware_enforced.unknown_tags
    assert desc.hardware_enforced.root_of_trust.device_locked is True


# ---------------------------------------------------------------- Apple


def _client_hash(challenge: bytes, key) -> bytes:
    return hashlib.sha256(enrollment_client_data(challenge, x963(key.public_key()))).digest()


def test_apple_ok(apple):
    signing = ec.generate_private_key(ec.SECP256R1())
    cdh = _client_hash(b"n" * 32, signing)
    res = verify_app_attest(apple.attestation(cdh), apple.key_id, cdh, apple_policy(apple))
    assert res.environment == "production"
    counter = verify_app_attest_assertion(apple.assertion(b"x" * 32, 1), b"x" * 32, res.public_key, [apple.app_id], 0)
    assert counter == 1
    with pytest.raises(EnrollmentError) as exc:
        verify_app_attest_assertion(apple.assertion(b"x" * 32, 1), b"x" * 32, res.public_key, [apple.app_id], 1)
    assert exc.value.code == "assertion_replayed"


@pytest.mark.parametrize(
    "auth,policy_kw,code",
    [
        ({"app_id": "ZZZZZ99999.com.other.app"}, {}, "app_mismatch"),
        ({"counter": 1}, {}, "attestation_malformed"),
        ({"aaguid": b"appattestdevelop"}, {}, "app_mismatch"),
        ({"cred_id": b"\x01" * 32}, {}, "attestation_key_mismatch"),
    ],
)
def test_apple_failures(apple, auth, policy_kw, code):
    cdh = b"h" * 32
    with pytest.raises(EnrollmentError) as exc:
        verify_app_attest(apple.attestation(cdh, **auth), apple.key_id, cdh, apple_policy(apple, **policy_kw))
    assert exc.value.code == code


def test_apple_development_allowed_when_configured(apple):
    cdh = b"h" * 32
    res = verify_app_attest(apple.attestation(cdh, aaguid=b"appattestdevelop"), apple.key_id, cdh, apple_policy(apple, allow_development=True))
    assert res.environment == "development"


def test_apple_client_data_binds_signing_key(apple):
    # Attestation made for one signing key cannot enroll another.
    k1, k2 = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    att = apple.attestation(_client_hash(b"n" * 32, k1))
    with pytest.raises(EnrollmentError) as exc:
        verify_app_attest(att, apple.key_id, _client_hash(b"n" * 32, k2), apple_policy(apple))
    assert exc.value.code == "challenge_mismatch"


def test_apple_untrusted_root(apple):
    cdh = b"h" * 32
    with pytest.raises(EnrollmentError) as exc:
        verify_app_attest(apple.attestation(cdh), apple.key_id, cdh, ApplePolicy(app_ids=[apple.app_id]))
    assert exc.value.code == "attestation_untrusted_root"


# ---------------------------------------------------------------- Enroller end to end


def _pop(key, nonce: bytes) -> str:
    return b64encode(key.sign(proof_of_possession_message(nonce), ec.ECDSA(hashes.SHA256())))


def _enroller(android=None, apple=None) -> Enroller:
    policy = EnrollmentPolicy(
        android=android_policy(android) if android else None,
        apple=apple_policy(apple) if apple else None,
    )
    return Enroller(policy=policy, registry=InMemoryKeyRegistry())


def test_enroller_android_end_to_end(android):
    enr = _enroller(android=android)
    ch = enr.issue_challenge("policy-123")
    req = {
        "enrollment_version": 1,
        "challenge_id": ch.challenge_id,
        "platform": "android",
        "signing_public_key": b64encode(x963(android.signing_key.public_key())),
        "proof_of_possession": _pop(android.signing_key, ch.nonce),
        "android": {"attestation_chain": [b64encode(c) for c in android.chain(ch.nonce)]},
    }
    rec = enr.enroll(req, "policy-123")
    assert rec.platform == "android" and rec.security_level == "STRONGBOX" and rec.account_ref == "policy-123"
    assert enr.registry.get(rec.fingerprint) is not None
    with pytest.raises(EnrollmentError) as exc:
        enr.enroll(req, "policy-123")
    assert exc.value.code == "challenge_unknown"


def _register_android(enr, fixture, account):
    ch = enr.issue_challenge(account)
    return enr.enroll({
        "challenge_id": ch.challenge_id,
        "platform": "android",
        "signing_public_key": b64encode(x963(fixture.signing_key.public_key())),
        "proof_of_possession": _pop(fixture.signing_key, ch.nonce),
        "android": {"attestation_chain": [b64encode(c) for c in fixture.chain(ch.nonce)]},
    }, account)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_enrollment_never_replaces_existing_records(backend, tmp_path, android):
    db = str(tmp_path / "registry.sqlite")
    reg = InMemoryKeyRegistry() if backend == "memory" else SqliteKeyRegistry(db)
    try:
        enr = Enroller(EnrollmentPolicy(android=android_policy(android)), reg)
        first = _register_android(enr, android, "policy-A")
        original = first.to_dict()
        for account in ("policy-A", "policy-B"):
            with pytest.raises(EnrollmentError) as exc:
                _register_android(enr, android, account)
            assert exc.value.code == "key_already_enrolled"
            assert reg.get(first.fingerprint).to_dict() == original

        assert reg.revoke(first.fingerprint, "device retired")
        revoked = reg.get(first.fingerprint).to_dict()
        assert revoked["status"] == "revoked" and revoked["revoked_reason"] == "device retired"
        with pytest.raises(EnrollmentError) as exc:
            _register_android(enr, android, "policy-A")
        assert exc.value.code == "key_already_enrolled"
        assert reg.get(first.fingerprint).to_dict() == revoked
        # A newly generated signing key can still be enrolled to that account.
        android.signing_key = ec.generate_private_key(ec.SECP256R1())
        replacement = _register_android(enr, android, "policy-A")
        assert replacement.active and replacement.fingerprint != first.fingerprint
        assert len(list(reg.list())) == 2
        assert reg.get(first.fingerprint).to_dict() == revoked
    finally:
        if backend == "sqlite":
            reg.close()
    if backend == "sqlite":
        reopened = SqliteKeyRegistry(db)
        try:
            assert reopened.get(first.fingerprint).to_dict() == revoked
        finally:
            reopened.close()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_concurrent_registration_has_one_winner(backend, tmp_path, android):
    # Exercise independent SQL connections and the shared in-memory registry.
    db = str(tmp_path / "registry.sqlite")
    first = InMemoryKeyRegistry() if backend == "memory" else SqliteKeyRegistry(db)
    second = first if backend == "memory" else SqliteKeyRegistry(db)
    try:
        pub = x963(android.signing_key.public_key())
        gate = Barrier(2)

        def insert(reg, account):
            record = KeyRecord.manual(pub, account)
            gate.wait(timeout=10)
            return reg.insert_if_absent(record), record

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(insert, reg, account) for reg, account in
                       ((first, "policy-A"), (second, "policy-B"))]
            outcomes = [f.result() for f in futures]
        assert sorted(ok for ok, _ in outcomes) == [False, True]
        winner = next(record for ok, record in outcomes if ok)
        assert second.get(winner.fingerprint).to_dict() == winner.to_dict()
    finally:
        if backend == "sqlite":
            first.close()
            second.close()


def test_legacy_enrollment_store_requires_atomic_insert(android):
    class LegacyStore:
        def put(self, record):
            pytest.fail("legacy upsert must never be used for enrollment")

    enr = Enroller(EnrollmentPolicy(android=android_policy(android)), LegacyStore())
    with pytest.raises(EnrollmentError) as exc:
        _register_android(enr, android, "policy-A")
    assert exc.value.code == "registry_unsupported"


def test_manual_cli_cannot_replace_revoked_registration(tmp_path, android, capsys):
    from verasnap_verify.cli import main
    db = str(tmp_path / "keys.sqlite")
    keys = ["keys", "--registry", db]
    pub = b64encode(x963(android.signing_key.public_key()))
    add = keys + ["add", "--public-key", pub, "--account", "policy-A"]
    assert main(add) == 0
    fp = capsys.readouterr().out.strip()
    assert main(keys + ["revoke", fp, "--reason", "lost"]) == 0
    assert main(keys + ["show", fp]) == 0
    before = json.loads(capsys.readouterr().out)
    assert main(add) == 3
    assert "already has a registry record" in capsys.readouterr().err
    assert main(keys + ["show", fp]) == 0
    after = json.loads(capsys.readouterr().out)
    assert before == after
    assert after["status"] == "revoked" and after["revoked_reason"] == "lost"


def test_enroller_ios_end_to_end(apple):
    enr = _enroller(apple=apple)
    signing = ec.generate_private_key(ec.SECP256R1())
    ch = enr.issue_challenge("policy-9")
    cdh = _client_hash(ch.nonce, signing)
    req = {
        "challenge_id": ch.challenge_id,
        "platform": "ios",
        "signing_public_key": b64encode(x963(signing.public_key())),
        "proof_of_possession": _pop(signing, ch.nonce),
        "ios": {"app_attest_key_id": b64encode(apple.key_id), "attestation_object": b64encode(apple.attestation(cdh))},
    }
    rec = enr.enroll(req, "policy-9")
    assert rec.platform == "ios" and rec.app_attest_sign_count == 0
    assert rec.attestation["type"] == "apple_app_attest"


def test_enroller_rejects_wrong_account_and_bad_pop(android):
    enr = _enroller(android=android)
    ch = enr.issue_challenge("policy-A")
    req = {
        "challenge_id": ch.challenge_id,
        "platform": "android",
        "signing_public_key": b64encode(x963(android.signing_key.public_key())),
        "proof_of_possession": _pop(android.signing_key, ch.nonce),
        "android": {"attestation_chain": [b64encode(c) for c in android.chain(ch.nonce)]},
    }
    with pytest.raises(EnrollmentError) as exc:
        enr.enroll(req, "policy-B")
    assert exc.value.code == "challenge_mismatch"

    ch2 = enr.issue_challenge("policy-A")
    other = ec.generate_private_key(ec.SECP256R1())
    req2 = dict(req, challenge_id=ch2.challenge_id, proof_of_possession=_pop(other, ch2.nonce))
    with pytest.raises(EnrollmentError) as exc:
        enr.enroll(req2, "policy-A")
    assert exc.value.code == "proof_of_possession_invalid"


def test_enroller_expired_challenge(android):
    enr = _enroller(android=android)
    ch = enr.issue_challenge("policy-A")
    req = {"challenge_id": ch.challenge_id, "platform": "android", "signing_public_key": "", "android": {}}
    with pytest.raises(EnrollmentError) as exc:
        enr.enroll(req, "policy-A", now=NOW + timedelta(hours=1))
    assert exc.value.code == "challenge_expired"


def test_enrolled_key_turns_proof_green(android):
    """An enrolled key is what lifts a valid proof from yellow to green."""
    import base64
    from pathlib import Path

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    here = Path(__file__).parent / "fixtures" / "scenarios"
    manifest = json.loads((here / "manifest.json").read_text())
    s01 = next(s for s in manifest["scenarios"] if s["id"] == "S01")
    proof = (here / s01["proof"]).read_bytes()
    photo = (here / "media" / "photo.jpg").read_bytes()

    registry = InMemoryKeyRegistry()
    assert Verifier(registry=registry).verify(proof, photo).level == "yellow"

    device_key = load_pem_private_key((here / "keys" / "device_enrolled.pem").read_bytes(), None)
    fx = AndroidFixture()
    fx.signing_key = device_key
    enr = Enroller(policy=EnrollmentPolicy(android=android_policy(fx)), registry=registry)
    ch = enr.issue_challenge("policy-777")
    enr.enroll(
        {
            "challenge_id": ch.challenge_id,
            "platform": "android",
            "signing_public_key": base64.b64encode(x963(device_key.public_key())).decode(),
            "proof_of_possession": _pop(device_key, ch.nonce),
            "android": {"attestation_chain": [b64encode(c) for c in fx.chain(ch.nonce)]},
        },
        "policy-777",
    )
    result = Verifier(registry=registry).verify(proof, photo)
    assert result.level == "green"
    assert result.signer.account_ref == "policy-777" and result.signer.known


# ---------------------------------------------------------------- real device chains (google/android-key-attestation)

SAMPLES = __import__("pathlib").Path(__file__).parent / "fixtures" / "android_google_samples"


def _sample(name):
    from verasnap_verify.enroll.android import _AttCert

    chain = [(SAMPLES / name / f"cert{i}.der").read_bytes() for i in range(4)]
    leaf = _AttCert.load(chain[0])
    desc = parse_key_description(leaf.key_description)
    return chain, leaf, desc


def test_real_tee_chain_verifies_against_bundled_google_root():
    chain, leaf, desc = _sample("algorithm_EC_SecurityLevel_TEE")
    app = desc.lookup("application_id")
    lenient = AndroidPolicy(
        package_names=list(app.package_names),
        signing_cert_sha256=list(app.signature_digests),
        require_verified_boot=False,
        require_locked_bootloader=False,
    )
    res = verify_android_attestation(chain, leaf.spki, desc.attestation_challenge, lenient, now=NOW)
    assert res.security_level is SecurityLevel.TRUSTED_ENVIRONMENT
    assert "f92009e853b6b045" in res.root_subject

    strict = AndroidPolicy(package_names=list(app.package_names), signing_cert_sha256=list(app.signature_digests))
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(chain, leaf.spki, desc.attestation_challenge, strict, now=NOW)
    assert exc.value.code == "device_integrity"


def test_real_strongbox_leaf_parses_and_test_root_is_rejected():
    chain, leaf, desc = _sample("algorithm_EC_SecurityLevel_StrongBox")
    assert desc.attestation_security_level is SecurityLevel.STRONGBOX
    assert desc.hardware_enforced.ec_curve is None  # omitted by this StrongBox
    app = desc.lookup("application_id")
    policy = AndroidPolicy(package_names=list(app.package_names), signing_cert_sha256=list(app.signature_digests))
    with pytest.raises(EnrollmentError) as exc:
        verify_android_attestation(chain, leaf.spki, desc.attestation_challenge, policy, now=NOW)
    assert exc.value.code == "attestation_untrusted_root"
