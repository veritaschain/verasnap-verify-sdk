# Real Android Key Attestation sample chains

Copied unchanged from https://github.com/google/android-key-attestation
(`src/test/resources/der/`, commit f9846cd), licensed under the Apache License 2.0.

- `algorithm_EC_SecurityLevel_TEE`: chain to Google's RSA attestation root
  (serial f92009e853b6b045; the device carries the 2016 copy, Google re-issued
  the root with the same key in 2022). Development device: bootloader unlocked,
  verified boot UNVERIFIED.
- `algorithm_EC_SecurityLevel_StrongBox`: leaf certificate with a non-strict
  ECDSA AlgorithmIdentifier and no TAG_EC_CURVE; chain ends at a root that is
  not a production Google root.
