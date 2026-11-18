# Changelog

## 0.1.0 — 2026-11-18

First release (alpha).

- Proof verification ported from VeraSnap iOS `ProofVerificationService` 1.6 with the 1.6.1 rules: signer-key origin check, capture time vs. TSA time (60-minute / 5-minute limits), TSA time taken only from a fully verified token, attestation reported as stated.
- Formats: shareable proof JSON (1.2, with or without `raw_event`), internal `proof.json`, Evidence Pack ZIP.
- Port of the apps' JSON canonicalizer, including its differences from RFC 8785.
- RFC 3161 verification: PKIStatus, TSTInfo, messageImprint (SHA-256), signed attributes, ESSCertID / ESSCertIDv2, EKU (timeStamping only, critical), CMS signature, chain at genTime. Bundled roots for DigiCert, Sectigo/USERTrust, Apple and GlobalSign.
- Merkle batch verification as in the apps.
- Device-key enrollment: Android Key Attestation (Google roots bundled, revocation list, verified boot, locked bootloader, package and signing digest, lenient parsing of non-strict device certificates) and Apple App Attest (attestation and assertions) with challenge, account binding and proof of possession.
- Key registry (in-memory, SQLite), CLI, reference HTTP server example.
- Tests: 125, including 31 fraud scenarios with real timestamps, and tests against real Android attestation chains from google/android-key-attestation.
