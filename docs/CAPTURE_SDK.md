# Capture SDK for insurers' apps — design (not yet implemented)

**Status:** design only. Available to insurers for proof-of-concept work under contract. Nothing in this document is shipped code.

The capture SDK embeds VeraSnap's sealing camera in an insurer's own claims app (native or LINE mini app WebView bridge), so photos for a claim are sealed at capture by a device key enrolled to the customer.

## Planned surface

```swift
// iOS (Swift Package)
let sdk = VeraSnapCapture(configuration: .init(enrollURL: …, appIdentifier: "TEAMID.com.example.claims"))
try await sdk.enrollIfNeeded(session: authenticatedSession)      // docs/ENROLLMENT.md
let capture = try await sdk.capturePhoto(from: viewController)   // camera UI; no gallery import
capture.media        // Data, the exact bytes that were sealed
capture.proof        // shareable proof JSON (proof_version 1.2)
```

```kotlin
// Android (AAR)
val sdk = VeraSnapCapture(context, CaptureConfig(enrollUrl = …, packageName = "com.example.claims"))
sdk.enrollIfNeeded(session)
val capture = sdk.capturePhoto(activity)   // CameraX; no gallery import
```

## Behaviour

- Camera only. Files from the gallery cannot be sealed.
- One key per install, created in Secure Enclave / StrongBox (TEE fallback), enrolled once with the insurer's server.
- Each capture: event built and signed as in VeraSnap 1.6.1; RFC 3161 timestamp requested immediately when online, otherwise batched and anchored on reconnect (then the 60-minute rule shows it as yellow).
- Output is verified server-side with this SDK. No VeritasChain server is in the data path.

## Prerequisites before a PoC

- CPP v1.7 Capture Environment Attestation modules agreed with the insurer (per-capture App Attest assertion / Play Integrity binding).
- Android first for C2PA Assurance Level 2 work (Android Key Attestation offers the clearer path).
- Independent evaluation of screen re-photography detection if it is to be used in claims decisions.
