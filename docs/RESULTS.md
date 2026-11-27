# Result reference

`Verifier.verify()` returns a `VerificationResult`. `result.to_dict()` / `to_json()` give the same content as JSON.

## Overall status

| Rule (in order) | Status | Level |
|---|---|---|
| A check failed, and it is `signature` | `SIGNATURE_INVALID` | red |
| A check failed, and it is `event_hash` or `media_hash` | `HASH_MISMATCH` | red |
| Any other check failed | `ERROR` | red |
| No failure, at least one warning | `PARTIALLY_VERIFIED` | yellow |
| No failure, no warning, timestamp fully verified | `ANCHOR_VERIFIED` | green |
| No failure, no warning, no fully verified timestamp | `ANCHOR_PENDING` | yellow |

`skipped` and `info` checks never change the status. These rules are those of the VeraSnap apps 1.6.1. A green proof may have `media_verified: false` or a manually registered key. For claim routing, check the [insurer integration conditions](INTEGRATION.md#minimal-integration).

## Fields

| Field | Content |
|---|---|
| `status`, `level` | As above |
| `summary` | One paragraph for a claims handler (English) |
| `format` | `shareable` or `internal` |
| `proof_id`, `event_id`, `proof_version` | From the proof |
| `capture_time_device` | Capture time covered by the signature. It is the device clock's value, not proven. `null` when not signed. |
| `timestamp_time`, `timestamp_authority` | genTime and signer of the RFC 3161 token, only when the token was fully verified |
| `media_verified` | `true` only if a file was supplied and matches the signed hash |
| `signer` | `public_key`, `fingerprint` (SHA-256 of the X9.63 key), `short_fingerprint` (first 8 bytes, as the apps show), `known`, `account_ref`, `platform`, `security_level`, `enrollment_status` |
| `chain_context` | As written in the proof. Not covered by the signature. |
| `checks` | List of `{id, status, code, message, details}` |
| `rules` | `verasnap-1.6.1` |

## Checks and codes

Integrators should key their own wording and routing on `id` and `code`; `message` is English text for logs.

| id | status | code | Meaning |
|---|---|---|---|
| `parse` | passed | `shareable` / `internal` | Format recognised |
| | failed | `invalid` | Not JSON, or not a VeraSnap proof |
| `event_hash` | passed | `match` | EventHash recomputed from the signed event |
| | warning | `raw_event_missing` | Shareable proof without `raw_event`: format checked only |
| | warning | `unsigned_fields` | Internal proof.json matches only after dropping fields the signature does not cover (listed in `details`) |
| | failed | `mismatch` | Event edited |
| | failed | `raw_event_inconsistent` | `raw_event` is intact but the `event` section was edited |
| | failed | `raw_event_invalid` / `format_invalid` | Undecodable `raw_event` or malformed EventHash |
| `signature` | passed | `valid` | ES256 over the recomputed EventHash |
| | failed | `invalid` / `malformed` / `no_public_key` | |
| `signer_key` | passed | `known` | Key enrolled with hardware attestation |
| | passed | `known_unattested` | Key registered by hand (`KeyRecord.manual`) |
| | warning | `unknown` | Valid signature by a key that is not enrolled |
| | warning | `revoked` | Key enrolled, then revoked |
| `media_hash` | passed | `match` | File matches the signed asset hash |
| | warning | `not_bound` | Matches a hash that the signature does not cover |
| | failed | `mismatch` | File edited, re-encoded or replaced |
| | skipped | `not_provided` | No file supplied |
| `merkle_inclusion` | passed | `match` | Event included in the anchored root |
| | warning | `proof_omitted` | Batch anchor without Merkle proof |
| | failed | `mismatch` / `invalid_token` | |
| `message_imprint` | passed / failed | `match` / `mismatch` | Token issued for this proof's digest |
| `tsa_signature` | passed | `valid` | CMS signature, ESSCertID, EKU and chain valid |
| | warning | `untrusted_chain` | Signature valid, chain not trusted |
| `timestamp` | passed | `verified` | RFC 3161 token fully verified |
| | warning | `untrusted_chain` / `unverifiable` / `missing_token` | Time cannot be relied on |
| | failed | `invalid` / `missing` / `anchor_digest_mismatch` | Token invalid, stripped or replayed |
| `capture_time` | passed | `within_limit` | Timestamp within 60 minutes after the recorded capture time |
| | warning | `anchor_delayed` | Timestamp more than 60 minutes after capture: capture date and time not independently confirmed |
| | warning | `capture_after_timestamp` | Recorded capture time more than 5 minutes after the timestamp: device clock wrong or changed |
| | warning | `unreadable` | |
| | skipped | `not_bound` / `no_verified_timestamp` | Nothing reliable to compare |
| `attestation` | info | `stated` | Attestation type written in the proof; not verified (see LIMITATIONS) |
| `human_attestation` | info | `recorded` / `recorded_failed` | A biometric check was recorded; it does not identify the photographer; counted only for enrolled keys |
| `chain_context` | info | `present` / `deletions_recorded` | Unsigned capture-history summary |

The 60- and 5-minute limits are `Verifier(max_anchor_delay=…, max_clock_ahead=…)`.
