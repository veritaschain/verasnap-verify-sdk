# Limitations and known gaps (0.1.0)

## What no capture proof can show

- **Staged reality.** Damage made deliberately, an old dent photographed again, another vehicle, a printed or on-screen picture photographed with a real camera: a genuine capture of a false scene verifies. Use loss adjusters, vehicle identity checks (plate, VIN in frame) and your fraud analytics.
- **Who took the photo.** VeraSnap records that a biometric check ran on the device and its result; it does not identify a person. In organised fraud the policyholder often takes the photo willingly.
- **Repair-shop and agent fraud.** If a business takes the photos on its own enrolled device, a proof shows that business captured them then; it does not stop inflated damage.

## What this version does not verify

- **Attestation written inside proofs** (`KeyAttestation`, `CaptureAssertion`, Android security level) is reported as *stated, not verified* — the same as the apps 1.6.1. Trust in the device comes only from **enrollment**. Verifying per-capture App Attest assertions and Play Integrity verdicts is planned with CPP v1.7 Capture Environment Attestation.
- **Camera injection on compromised devices.** On Android, enrollment requires a verified boot state and a locked bootloader (KeyMint attests both). On iOS, App Attest proves a genuine app binary but does not reliably detect jailbreaks. Virtual-camera and sensor injection detection (CEA) is not implemented.
- **Screen re-photography.** The apps record multi-modal screen checks (vendor-measured ~96% detection, not independently evaluated). The SDK does not use or score them.
- **Location.** GPS values are device statements; GNSS spoofing is not detected.
- **TSA revocation.** CRL/OCSP are not checked (as in the apps). Chains are validated at genTime against the bundled roots.
- **Chain context** (`chain_context` / `ChainContext`) is not covered by the signature. Deletion counts are shown as an unsigned hint.
- **Capture time** is the device clock. A timestamp proves only that the proof existed no later than genTime; the 60-minute rule limits how far back a capture can be dated without a warning.

## Differences from the VeraSnap apps (all deliberate)

| Topic | Apps 1.6.1 | SDK 0.1.0 |
|---|---|---|
| Known signing keys | This device's key only | Keys in the insurer's registry, enrolled through attestation |
| Internal `proof.json` EventHash | Recomputed through the iOS 1.6 verification model, which drops unknown fields (iOS events carrying `CaptureAssertion` fail; known gap) | The event exactly as written first; the iOS model only as a fallback, and then fields outside the signature are a warning (`unsigned_fields`) |
| TSA trust | iOS system trust store | Bundled roots (DigiCert G4, USERTrust, Sectigo R46, Apple Root CA, GlobalSign R45); replaceable |
| Revoked keys | n/a | Warning (`signer_key/revoked`) |
| Summary wording | "Photo integrity confirmed" on yellow results | Said only when the signer is known |

## Not claimed

- No C2PA conformance (VeritasChain has filed an expression of interest only).
- No independent security audit yet.
- No claim that any court, regulator or insurer will accept a proof.
- The Merkle construction matches the apps (no 0x00/0x01 domain separation), not yet draft-vso-cpp-core.
