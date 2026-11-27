# VeraSnap Verify SDK

Server-side verification of VeraSnap / CPP capture proofs, and enrollment of device signing keys — for insurers and other organisations that receive photos as evidence.

[日本語版 README](README.ja.md) · [Integration guide](docs/INTEGRATION.md) · [Enrollment](docs/ENROLLMENT.md) · [Result codes](docs/RESULTS.md) · [Limitations](docs/LIMITATIONS.md) · [Capture SDK (planned)](docs/CAPTURE_SDK.md)

> **Status (alpha).** The [v0.1.0 release](https://github.com/veritaschain/verasnap-verify-sdk/releases/tag/v0.1.0) passed 125 tests. The development revision pinned below passed 196 tests in [first-party CI](https://github.com/veritaschain/verasnap-verify-sdk/actions/runs/46006502792), including repeat-registration checks, Android attestation issuer and path-constraint checks, 31 fraud scenarios with real RFC 3161 timestamps, and tests against real Android attestation chains. These are first-party tests, not independent validation. The capture SDK for insurers' own apps is in design. APIs may change before 1.0.

## What it does

A claims system receives a photo and its VeraSnap proof. The SDK answers, with checks you can audit:

- Was this exact file sealed at capture, and has it changed since? (SHA-256, ES256 signature)
- Was the proof timestamped by an independent authority, and when? (RFC 3161, full CMS and chain validation)
- Was it signed by a device key that **you** enrolled, through hardware attestation? (Android Key Attestation, Apple App Attest)
- Is the recorded capture time consistent with the timestamp? (the 60-minute rule of the VeraSnap apps)
- Does the event's Merkle inclusion proof match the supplied batch root? Capture-history deletion counts are unsigned hints. Checking inclusion of this event cannot establish that all expected captures are present.

It does **not** judge what the picture shows. A real camera can photograph staged damage. *Provenance is not truth.*

## Install

Use Python 3.10 or later. Install the development revision below for the documented CLI and insurance-routing example. It includes the following post-release enrollment fixes. [The fix for repeat registration](https://github.com/veritaschain/verasnap-verify-sdk/pull/1): enrollment and manual `keys add` now reject a known fingerprint and preserve its existing record, including any revocation. [The Android attestation path fix](https://github.com/veritaschain/verasnap-verify-sdk/pull/3): Android enrollment now checks each issuer's CA status, key usage and path length, and rejects malformed chains and constraints it does not support. The Apple and timestamp helpers are unchanged, and this is not a general PKIX validator.

```bash
python -m pip install "verasnap-verify @ git+https://github.com/veritaschain/verasnap-verify-sdk.git@1f1289ef21fea84393d42a36ee10152c25cae70e"
```

If v0.1.0 and its dependencies are already installed, force the SDK reinstall because both revisions report version `0.1.0`.

```bash
python -m pip install --force-reinstall --no-deps "verasnap-verify @ git+https://github.com/veritaschain/verasnap-verify-sdk.git@1f1289ef21fea84393d42a36ee10152c25cae70e"
```

Custom enrollment stores must now implement atomic insertion through [`insert_if_absent`](docs/ENROLLMENT.md). If a revocation record may already have been overwritten, reconcile the registry with independent audit records or a backup because upgrading cannot reconstruct that history.

Dependencies: `cryptography`, `asn1crypto`, `cbor2`. No network access at verification time.

## Quick start

```python
from verasnap_verify import Verifier, SqliteKeyRegistry

verifier = Verifier(registry=SqliteKeyRegistry("keys.sqlite"))
result = verifier.verify(open("proof.json", "rb").read(), media=open("photo.jpg", "rb").read())

result.level          # "green" | "yellow" | "red"
result.status         # ANCHOR_VERIFIED, PARTIALLY_VERIFIED, ANCHOR_PENDING, SIGNATURE_INVALID, HASH_MISMATCH, ERROR
result.summary        # one paragraph for a claims handler
result.checks         # each check with a stable id and code
result.timestamp_time # genTime of a fully verified token only
result.signer.account_ref  # the enrolled customer, if the key is known
print(result.to_json())
```

Accepted inputs: shareable proof JSON (`proof_version` 1.2, snake_case), internal `proof.json` (PascalCase), or an Evidence Pack ZIP (`media.*` + `proof.json`).

Command line:

```bash
verasnap-verify verify proof.json --media photo.jpg --registry keys.sqlite
verasnap-verify verify evidence_pack.zip --json
verasnap-verify keys --registry keys.sqlite add --public-key <Base64> --account policy-123
```

Exit codes: 0 green, 1 yellow, 2 red, 3 input error.

## Statuses

| Level | Status | Meaning |
|---|---|---|
| green | `ANCHOR_VERIFIED` | The timestamp was fully verified and no check failed or warned. An omitted photo leaves the media check skipped. A manually registered key can pass the signer check. |
| yellow | `PARTIALLY_VERIFIED` | No check failed, but something could not be confirmed (unknown key, late timestamp, untrusted TSA, Merkle proof omitted, raw event missing…). |
| yellow | `ANCHOR_PENDING` | Signature valid, but no fully verified timestamp. |
| red | `SIGNATURE_INVALID` / `HASH_MISMATCH` / `ERROR` | The photo or proof does not match, or the proof was altered. |

Green means only that the proof meets VeraSnap's verification criteria. The capture time is the device clock's value. Details: [docs/RESULTS.md](docs/RESULTS.md).

## Why key enrollment matters

Anyone can generate a P-256 key, sign an AI-edited image and buy a genuine RFC 3161 timestamp. That proof has a valid signature and a valid timestamp. What it cannot have is a key that was created inside a genuine device for your app and enrolled to a customer through hardware attestation. So:

- active keys enrolled through hardware attestation pass with code `known`. An active manually registered key passes with `known_unattested` and can also produce **green**; check the code before relying on hardware origin;
- unknown signing keys, including unregistered consumer-app keys, produce **yellow** at best under the default verification policy.

The `verasnap_verify.enroll` module verifies Android Key Attestation chains (Google roots bundled, revocation list supported, verified boot and locked bootloader required by default) and Apple App Attest attestations (Apple root bundled) whose client data commits to the signing key. See [docs/ENROLLMENT.md](docs/ENROLLMENT.md).

## Recommended claims flow

1. Consider a photo for fast-track review when its proof is green, `media_verified` is true, the `signer_key` check passed with code `known` (hardware-attested enrollment), and `signer.account_ref` matches the expected account from the claim system. A green result alone goes through normal review.
2. Photos without a proof: your existing post-hoc AI-image detection.
3. Doubtful claims: ask for new photos taken with the capture SDK in your app.

This complements post-hoc detection; it does not replace it. See [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Compatibility

The verification rules follow the VeraSnap apps 1.6.1 (iOS is the reference, Android follows it): EventHash over the apps' canonical JSON, ES256 over the EventHash digest, Merkle batches (leaf = SHA-256(EventHash), no domain separation), RFC 3161 with ESSCertID/v2, EKU and chain checked at genTime, the signer-key origin check and the 60-minute rule. Where the SDK is stricter or more complete than the app, [docs/LIMITATIONS.md](docs/LIMITATIONS.md) lists it.

## Tests

```bash
pip install -e ".[test]" && pytest
```

`tests/fixtures/scenarios` holds 31 scenarios (edited, re-encoded and swapped photos; forged proofs with an attacker's key and a real timestamp; backdating; stripped or swapped timestamps; batch anchoring; internal proof.json; Evidence Pack). They were built by `tools/make_fixtures.py` the way the apps build proofs, with real timestamps from rfc3161.ai.moda, DigiCert and Sectigo. The private keys under `tests/fixtures/scenarios/keys` are test keys only.

## Disclosure

This SDK is a first-party implementation by VeritasChain Co., Ltd., which operates the VeritasChain Standards Organization (VSO), the specification initiative that publishes CPP. It has not been independently audited. It is not C2PA-certified. It does not determine whether a court, regulator or insurer will accept a proof.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Contact: developers@veritaschain.org
