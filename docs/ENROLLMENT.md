# Device key enrollment

Enrollment binds a device signing key to one of your customers, after checking with Google or Apple hardware attestation that the key belongs to a genuine instance of **your** app on a genuine device. Proofs signed by enrolled keys can be green; all other proofs are yellow at best.

## Flow

```
App (capture SDK)                         Your server (this SDK)
-----------------                         ----------------------
                         1. authenticated session
                  ─────────────────────────▶ challenge = enroller.issue_challenge(account_ref)
                  ◀───────────────────────── {challenge_id, challenge, expires_at}
2. create P-256 signing key in hardware,
   attest it with the challenge,
   sign the PoP message
                  ─────────────────────────▶ record = enroller.enroll(request, account_ref)
                  ◀───────────────────────── {fingerprint, security_level}
3. later: every capture is signed with this key; proofs verify with `known` signer
```

`account_ref` always comes from your own authenticated session, never from the request body. Challenges are 32 random bytes, single use, valid 5 minutes by default, and bound to the `account_ref` they were issued for.

## Server

```python
from verasnap_verify import SqliteKeyRegistry
from verasnap_verify.enroll import AndroidPolicy, ApplePolicy, Enroller, EnrollmentError, EnrollmentPolicy, SecurityLevel

policy = EnrollmentPolicy(
    android=AndroidPolicy(
        package_names=["com.example.claims"],
        signing_cert_sha256=[bytes.fromhex("…")],      # SHA-256 of your app signing certificate (Play App Signing key)
        min_security_level=SecurityLevel.TRUSTED_ENVIRONMENT,  # or STRONGBOX
        # require_verified_boot=True, require_locked_bootloader=True  (defaults)
        # revocation=RevocationList.from_json(<https://android.googleapis.com/attestation/status>)
    ),
    apple=ApplePolicy(app_ids=["TEAMID.com.example.claims"]),  # allow_development=False by default
)
enroller = Enroller(policy=policy, registry=SqliteKeyRegistry("keys.sqlite"))
```

Refresh Google's revocation list daily and pass it in; the SDK does no network I/O. Errors raise `EnrollmentError` with a stable `code` (`challenge_unknown`, `challenge_expired`, `challenge_mismatch`, `attestation_untrusted_root`, `attestation_revoked`, `attestation_security_level`, `device_integrity`, `app_mismatch`, `attestation_key_mismatch`, `proof_of_possession_invalid`, …).

## Request (JSON)

```json
{
  "enrollment_version": 1,
  "challenge_id": "…",
  "platform": "android",
  "signing_public_key": "<Base64, 65-byte X9.63 P-256 key>",
  "proof_of_possession": "<Base64 ES256 signature (DER or raw r||s)>",
  "android": { "attestation_chain": ["<Base64 DER leaf>", "…", "<Base64 DER root>"] }
}
```

```json
{
  "enrollment_version": 1,
  "challenge_id": "…",
  "platform": "ios",
  "signing_public_key": "<Base64, 65-byte X9.63 P-256 key>",
  "proof_of_possession": "<Base64 ES256 signature>",
  "ios": {
    "app_attest_key_id": "<Base64 key id from DCAppAttestService.generateKey>",
    "attestation_object": "<Base64 CBOR from attestKey>"
  }
}
```

Byte strings the app signs or hashes (`challenge` is the 32 decoded bytes):

| Name | Bytes |
|---|---|
| Proof of possession (both platforms) | `"VERASNAP-ENROLL-POP-v1" ‖ 0x00 ‖ challenge`, signed with ES256 (SHA-256) by the new signing key |
| iOS clientData | `"VERASNAP-ENROLL-v1" ‖ 0x00 ‖ challenge ‖ signing key (65 bytes)`; pass `SHA-256(clientData)` to `attestKey` |

## What is checked

**Android** (`verify_android_attestation`)

- chain signatures, ending at a Google hardware attestation root (bundled: RSA root re-issued 2022, ECDSA "Key Attestation CA1"); certificates valid now; optional revocation list;
- leaf key = the key being enrolled; `attestationChallenge` = the challenge;
- attestation and KeyMint security level ≥ policy (TEE by default);
- hardware-enforced: EC, P-256 (or curve omitted, as some StrongBox chips do, with the leaf key itself P-256), purpose SIGN, origin GENERATED;
- root of trust: verified boot state VERIFIED and bootloader locked (defaults);
- attestation application id: package name and signing-certificate digest allowed.

Tested against synthetic chains and against real device chains from google/android-key-attestation (including a StrongBox leaf that strict parsers reject).

**iOS** (`verify_app_attest`, Apple's steps 1–9)

- `x5c` chain to the Apple App Attestation Root CA (bundled);
- nonce `SHA-256(authData ‖ clientDataHash)` equals the credential certificate extension `1.2.840.113635.100.8.2`, where clientData commits to the challenge and the signing key;
- `SHA-256(credential public key)` = key id = credential id; RP ID hash = `SHA-256("TEAMID.bundle.id")`; counter 0; AAGUID production (development only if allowed).

`verify_app_attest_assertion` checks later assertions (counter must increase). Apple cannot attest a Secure Enclave key directly: what is proven is that a genuine instance of your app, on a genuine Apple device, asked to enroll that signing key.

## Client side (illustrative)

These are the platform calls the capture SDK will make. They are not shipped code yet.

```kotlin
// Android
val spec = KeyGenParameterSpec.Builder("claims_signing", KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(challenge)
    .setIsStrongBoxBacked(true)            // fall back to TEE on StrongBoxUnavailableException
    .build()
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()
val chain = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getCertificateChain("claims_signing")
```

```swift
// iOS
let signingKey = try SecureEnclave.P256.Signing.PrivateKey()
let clientData = Data("VERASNAP-ENROLL-v1".utf8) + Data([0]) + challenge + signingKey.publicKey.x963Representation
let keyId = try await DCAppAttestService.shared.generateKey()
let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
let pop = try signingKey.signature(for: Data("VERASNAP-ENROLL-POP-v1".utf8) + Data([0]) + challenge).derRepresentation
```
