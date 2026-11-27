# Integration guide for insurers

## Where it fits

Post-hoc detectors (AI-image classifiers, re-use matching) run on every photo, cost the customer nothing, and give probabilities. Capture-time proofs cover only photos taken through a sealing camera, cost the customer a step, and give yes/no answers that do not weaken as image generators improve. Use both, in series:

| Stage | Photos | Check | Outcome |
|---|---|---|---|
| 1 | With a proof from an enrolled key | `Verifier.verify(proof, photo)` | Check the fast-track conditions below; otherwise use normal review or refer |
| 2 | Without a proof (camera roll, LINE, web upload) | Your existing post-hoc detection | as today |
| 3 | Doubtful claims, high amounts | Ask for new photos with the capture SDK in your app | verify as stage 1 |

Making stage 3 mandatory only where it matters keeps the customer journey unchanged for most claims.

## Minimal integration

1. Receive the proof and the photo from your claims app or channel (shareable proof JSON, `proof.json`, or an Evidence Pack ZIP).
2. `result = Verifier(registry=…).verify(proof, photo)`.
3. Store `result.to_dict()` with the claim. It records the checks, the verified timestamp, the signer key and the SDK version.
4. For fast-track eligibility, require a green result, `result.media_verified`, a passed `signer_key` check with code `known`, and `result.signer.account_ref` equal to the expected account from your authenticated claim record. A manual registration reports `known_unattested`. If any condition is missing, use normal review or refer the claim. See the [routing example](../examples/verify_claim_photo.py).

A green proof can have a skipped media check when the photo was omitted. The handler still assesses what the photo depicts and whether it supports the claim. Merkle inclusion covers the selected event in the supplied batch. The capture history's deletion count is unsigned, so evaluating its completeness requires separate records.

## Suggested handling

| Result | Typical meaning | Suggested handling |
|---|---|---|
| green with all four conditions above | The supplied photo matches the signed digest and the attested key is registered to the expected account | Eligible for fast-track review under the insurer's policy |
| green with missing media, manual key registration, or missing/mismatched account | A required photo or enrollment check is outstanding | Normal review |
| yellow `signer_key/unknown` | Valid proof, but from a key you did not enroll (consumer app, or a forger's own key) | Treat as an unsealed photo (stage 2) |
| yellow `capture_time/anchor_delayed` | Captured offline or backdated; existed no later than the timestamp | Compare the timestamp with the reported accident date |
| yellow `timestamp/untrusted_chain` | TSA not in your trust store | Review your trust store; otherwise stage 2 |
| red `media_hash/mismatch` | Photo edited, re-encoded or replaced after sealing | Ask for the original file; refer if repeated |
| red `signature`, `event_hash`, `timestamp` failures | Proof altered or stripped | Refer |

## Data and privacy

- Verification is offline and needs only the proof and the file. No image leaves your systems.
- The registry stores public keys, attestation summaries and your opaque `account_ref`; no biometric data. VeraSnap's biometric check is recorded only as a flag and method; it does not identify the photographer.
- Location in VeraSnap proofs is stored as hashes in the signed event; precise coordinates appear only in internal exports that the user chooses to share.

## Operations

- Keep the SDK's trust data current: Google may rotate attestation roots (two are bundled); TSA roots are listed in `src/verasnap_verify/data/README.md`.
- Fetch Google's attestation status list daily if you enroll Android devices.
- Revoke keys on device loss or contract end: `registry.revoke(fingerprint, reason)`. Proofs from revoked keys are yellow.
- Pin the SDK version in production and record `result.sdk_version` and `result.rules` with each decision.
