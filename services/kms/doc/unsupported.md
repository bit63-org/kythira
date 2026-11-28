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
| `DeleteCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `DeleteImportedKeyMaterial` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `DeriveSharedSecret` | none | Not in the spec: ECDH key agreement on an ECC key pair (KMS added it after the spec was written). Open question for the owner. | `UnsupportedOperationException`, HTTP 400 |
| `DescribeCustomKeyStores` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `DisconnectCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `GetKeyLastUsage` | none | Not in the spec: when a key was last used (a recent KMS addition). Open question for the owner. | `UnsupportedOperationException`, HTTP 400 |
| `GetParametersForImport` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `ImportKeyMaterial` | out of scope | Imported key material is out of scope for this spec (design, "What stays out"): it needs an RSA-OAEP unwrap into a non-extractable HSM object, left for a follow-up spec. | `UnsupportedOperationException`, HTTP 400 |
| `ReplicateKey` | out of scope | Multi-Region keys are out of scope: they need key material replicated across regions' HSMs, which the virtual HSM does not do (design, "What stays out"). | `UnsupportedOperationException`, HTTP 400 |
| `UpdateCustomKeyStore` | out of scope | Custom key stores are out of scope: the virtual HSM's external-module support swaps the backing store for the whole KMS (design, "Metadata in the KMS, material in the HSM"). | `UnsupportedOperationException`, HTTP 400 |
| `UpdatePrimaryRegion` | out of scope | Multi-Region keys are out of scope: they need key material replicated across regions' HSMs, which the virtual HSM does not do (design, "What stays out"). | `UnsupportedOperationException`, HTTP 400 |

## Behaviour that differs inside implemented operations

- **A grant to an account's root principal** serves only that root
  principal. AWS also lets the account pass such a grant on to its users
  and roles through IAM policies; Kythira matches a grantee by exact ARN
  (the caller's ARN, or a role session's role ARN) and does not
  (`include/kythira/kms/kms_grants.hpp`).
- **Grants are in force once committed.** AWS documents grants as
  eventually consistent and offers grant tokens to use one at once; here
  every read passes a read barrier, so a committed grant applies to every
  request on every replica. Grant tokens are still accepted and checked
  (one this KMS did not make is `InvalidGrantTokenException`) but carry
  no authority of their own.

## Kythira extensions

These go beyond AWS KMS. An AWS SDK does not send them (botocore's model
has no such members), so they change nothing for an AWS client; Kythira's
own services call them through `kms.client` or signed JSON.

- **Decrypt for an HPKE recipient**
  (`.kiro/specs/ec2-compatible-api/` Requirements 10.2-10.3). AWS's
  `Recipient` takes a Nitro attestation document and returns the
  plaintext under the enclave's RSA key; that form still answers
  `UnsupportedOperationException`. Kythira's takes
  `KeyEncryptionAlgorithm` `KYTHIRA_HPKE_X25519_SHA256_AES256GCM` with
  three members, all required:

  | Member | What |
  |---|---|
  | `KythiraPublicKey` | the recipient's X25519 public key, 32 bytes |
  | `KythiraAssociatedData` | the HPKE associated data, 1-1024 bytes |
  | `KythiraInfo` | the HPKE info, which names the use, 1-1024 bytes |

  KMS opens the ciphertext as any Decrypt does (key policy, grants,
  encryption context), then seals the plaintext with HPKE (RFC 9180 base
  mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM,
  `include/kythira/kms/kms_hpke.hpp`) and returns it as
  `CiphertextForRecipient`: the 32-byte encapsulated key, then the
  ciphertext and its 16-byte tag. `Plaintext` and `KeyMaterialId` are
  left out, as AWS leaves them out with a Recipient. The EC2 controller
  uses it at `AttachVolume` to turn a lineage's wrapped data key into an
  antikythera `VolumeKey` for one helm, one attachment and one
  generation, with info `antikythera volume key v1` and the frame's
  header as associated data, so the controller never holds the key.

  The request is authorized as `kms:Decrypt` with the usual condition
  keys plus `kms:KythiraRecipientPublicKeySha256`, the lower-case hex
  SHA-256 of `KythiraPublicKey`. A lineage key's policy allows Decrypt
  only to the EC2 service principal, only with the lineage's
  encryption context, and only with this condition key, so the key
  leaves KMS sealed to a key the controller enrolled. Refusals: the
  Kythira members without the Kythira algorithm, `AttestationDocument`
  with it, or a missing member answer `ValidationException`, as does a
  low-order (all-zero shared secret) public key; the model refuses a key
  that is not 32 bytes and any member or algorithm it does not know.

