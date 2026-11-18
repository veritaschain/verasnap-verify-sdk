# VeraSnap Verify SDK

Server-side verification of VeraSnap / CPP capture proofs, and enrollment of device signing keys — for insurers and other organisations that receive photos as evidence.

[日本語版 README](README.ja.md) · [Integration guide](docs/INTEGRATION.md) · [Enrollment](docs/ENROLLMENT.md) · [Result codes](docs/RESULTS.md) · [Limitations](docs/LIMITATIONS.md) · [Capture SDK (planned)](docs/CAPTURE_SDK.md)

> **Status: 0.1.0 (alpha).** The verifier and the enrollment checks are complete and tested (125 tests, including 31 fraud scenarios with real RFC 3161 timestamps and real Android attestation chains). The capture SDK for insurers' own apps is a design, not yet code. APIs may change before 1.0.

## What it does

A claims system receives a photo and its VeraSnap proof. The SDK answers, with checks you can audit:

- Was this exact file sealed at capture, and has it changed since? (SHA-256, ES256 signature)
- Was the proof timestamped by an independent authority, and when? (RFC 3161, full CMS and chain validation)
- Was it signed by a device key that **you** enrolled, through hardware attestation? (Android Key Attestation, Apple App Attest)
- Is the recorded capture time consistent with the timestamp? (the 60-minute rule of the VeraSnap apps)
- Was anything removed from the capture history? (Merkle inclusion; chain context reported as a hint)

It does **not** judge what the picture shows. A real camera can photograph staged damage. *Provenance is not truth.*

## Install

Python 3.10 or later.

```bash
pip install git+https://github.com/veritaschain/verasnap-verify-sdk
```

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
verasnap-verify keys add --public-key <Base64> --account policy-123 --registry keys.sqlite
```

Exit codes: 0 green, 1 yellow, 2 red, 3 input error.

## Statuses

| Level | Status | Meaning |
|---|---|---|
| green | `ANCHOR_VERIFIED` | Every check passed: unchanged since signing, signed by an enrolled key, timestamp fully verified and obtained within 60 minutes of the recorded capture time. |
| yellow | `PARTIALLY_VERIFIED` | No check failed, but something could not be confirmed (unknown key, late timestamp, untrusted TSA, Merkle proof omitted, raw event missing…). |
| yellow | `ANCHOR_PENDING` | Signature valid, but no fully verified timestamp. |
| red | `SIGNATURE_INVALID` / `HASH_MISMATCH` / `ERROR` | The photo or proof does not match, or the proof was altered. |

Green means only that the proof meets VeraSnap's verification criteria. The capture time is the device clock's value. Details: [docs/RESULTS.md](docs/RESULTS.md).

## Why key enrollment matters

Anyone can generate a P-256 key, sign an AI-edited image and buy a genuine RFC 3161 timestamp. That proof has a valid signature and a valid timestamp. What it cannot have is a key that was created inside a genuine device for your app and enrolled to a customer through hardware attestation. So:

- proofs signed by enrolled keys can be **green**;
- proofs signed by any other key — including keys of the free consumer app — are **yellow** at best.

The `verasnap_verify.enroll` module verifies Android Key Attestation chains (Google roots bundled, revocation list supported, verified boot and locked bootloader required by default) and Apple App Attest attestations (Apple root bundled) whose client data commits to the signing key. See [docs/ENROLLMENT.md](docs/ENROLLMENT.md).

## Recommended claims flow

1. Photos with a proof from an enrolled key that verify green: fast track.
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

This SDK is a first-party implementation by VeritasChain Co., Ltd., which shares a founder with the VeritasChain Standards Organization that publishes CPP. It has not been independently audited. It is not C2PA-certified. It does not determine whether a court, regulator or insurer will accept a proof.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Contact: developers@veritaschain.org
