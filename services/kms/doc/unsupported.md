# KMS operations not implemented

`.kiro/specs/kms-compatible-api/` task 1: every operation in the pinned model
(`../model/service-2.json`, botocore 1.43.100) is either implemented, and
then listed in `../implemented-operations.txt`, or listed here with its
reason and the exact error it returns. `tools/check_coverage.py` (the ctest
`kms_model_coverage`) fails when an operation is in neither list, so a model
upgrade that adds one fails until it is placed.

Until the API listener exists (task 12) no request is served at all. Once it
does, an operation listed here is answered with `UnsupportedOperationException`
(HTTP 400), the error AWS KMS itself returns for an operation a key or
account cannot use, so SDKs surface it as a client error rather than a
retryable fault.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `ConnectCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `CreateCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `CreateGrant` | task 10 | Not built yet (grants). | `UnsupportedOperationException`, HTTP 400 |
| `Decrypt` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `DeleteCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `DeleteImportedKeyMaterial` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `DeriveSharedSecret` | none | Not in the spec: ECDH key agreement on an ECC key pair (KMS added it after the spec was written). Open question for the owner. | `UnsupportedOperationException`, HTTP 400 |
| `DescribeCustomKeyStores` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `DisableKeyRotation` | task 11 | Not built yet (rotation). | `UnsupportedOperationException`, HTTP 400 |
| `DisconnectCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `EnableKeyRotation` | task 11 | Not built yet (rotation). | `UnsupportedOperationException`, HTTP 400 |
| `Encrypt` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateDataKey` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateDataKeyPair` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateDataKeyPairWithoutPlaintext` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateDataKeyWithoutPlaintext` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateMac` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `GenerateRandom` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `GetKeyLastUsage` | none | Not in the spec: when a key was last used (a recent KMS addition). Open question for the owner. | `UnsupportedOperationException`, HTTP 400 |
| `GetKeyPolicy` | task 9 | Not built yet (key policies). | `UnsupportedOperationException`, HTTP 400 |
| `GetKeyRotationStatus` | task 11 | Not built yet (rotation). | `UnsupportedOperationException`, HTTP 400 |
| `GetParametersForImport` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `GetPublicKey` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `ImportKeyMaterial` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `ListGrants` | task 10 | Not built yet (grants). | `UnsupportedOperationException`, HTTP 400 |
| `ListKeyPolicies` | task 9 | Not built yet (key policies). | `UnsupportedOperationException`, HTTP 400 |
| `ListKeyRotations` | task 11 | Not built yet (rotation). | `UnsupportedOperationException`, HTTP 400 |
| `ListRetirableGrants` | task 10 | Not built yet (grants). | `UnsupportedOperationException`, HTTP 400 |
| `PutKeyPolicy` | task 9 | Not built yet (key policies). | `UnsupportedOperationException`, HTTP 400 |
| `ReEncrypt` | task 7 | Not built yet (symmetric operations). | `UnsupportedOperationException`, HTTP 400 |
| `ReplicateKey` | out of scope | Multi-Region keys are out of scope: they need key material replicated across regions' HSMs, which the virtual HSM does not do (design, "What stays out"). | `UnsupportedOperationException`, HTTP 400 |
| `RetireGrant` | task 10 | Not built yet (grants). | `UnsupportedOperationException`, HTTP 400 |
| `RevokeGrant` | task 10 | Not built yet (grants). | `UnsupportedOperationException`, HTTP 400 |
| `RotateKeyOnDemand` | task 11 | Not built yet (rotation). | `UnsupportedOperationException`, HTTP 400 |
| `Sign` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `UpdateCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `UpdatePrimaryRegion` | out of scope | Multi-Region keys are out of scope: they need key material replicated across regions' HSMs, which the virtual HSM does not do (design, "What stays out"). | `UnsupportedOperationException`, HTTP 400 |
| `Verify` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
| `VerifyMac` | task 8 | Not built yet (asymmetric and HMAC operations). | `UnsupportedOperationException`, HTTP 400 |
