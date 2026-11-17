#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
"""AWS clients against a Kythira KMS (.kiro/specs/kms-compatible-api/ task 18).

Runs three suites against the endpoints given, spreading calls over them so
that followers forward to the catalog's leader:

  * boto3: every key spec and operation family Kythira implements, the
    errors clients branch on, and local checks of what KMS hands out
    (public keys, data key pairs) with `cryptography`;
  * the AWS CLI v2 (`aws` on PATH, or --aws): create, alias, encrypt and
    decrypt through files, and a missing key's exit status;
  * the AWS Encryption SDK for Python: messages under one and two KMS keys,
    decrypted by a provider that knows only one of them.

Credentials come from the environment (AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY), as every AWS client takes them. --ca names the CA
bundle the endpoints' certificates chain to. A suite whose client is not
installed fails, unless --skip names it: CI installs all three.

Exit status 0 when every check passed; each failed check is printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import uuid
from typing import Callable


ACCOUNT = "111122223333"
REGION = "us-east-1"


class Checks:
    """Named checks; a failure is recorded and the run carries on."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def that(self, name: str, ok: bool, detail: str = "") -> None:
        if ok:
            self.passed += 1
        else:
            self.failed.append(f"{name}: {detail}" if detail else name)
            print(f"FAIL {name} {detail}", flush=True)

    def equal(self, name: str, got: object, want: object) -> None:
        self.that(name, got == want, f"got {got!r}, want {want!r}")

    def raises(self, name: str, code: str, call: Callable[[], object]) -> None:
        """`call` fails with the AWS error `code`."""
        from botocore.exceptions import ClientError

        try:
            call()
        except ClientError as e:
            got = e.response.get("Error", {}).get("Code", "")
            self.equal(name, got, code)
            return
        self.that(name, False, f"no error; want {code}")

    def run(self, name: str, suite: Callable[[], None]) -> None:
        print(f"== {name}", flush=True)
        try:
            suite()
        except Exception:  # noqa: BLE001 - a crashed suite is one failure
            self.failed.append(f"{name}: crashed\n{traceback.format_exc()}")
            print(f"FAIL {name} crashed\n{traceback.format_exc()}", flush=True)


class Clients:
    """boto3 clients, one per endpoint, used in turn."""

    def __init__(self, endpoints: list[str], ca: str) -> None:
        import boto3

        self._clients = [
            boto3.client("kms", endpoint_url=e, region_name=REGION, verify=ca) for e in endpoints
        ]
        self._next = 0

    def __call__(self):
        c = self._clients[self._next % len(self._clients)]
        self._next += 1
        return c


def boto3_suite(c: Checks, kms: Clients) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    # -- Symmetric keys -------------------------------------------------------
    made = kms().create_key(Description="boto3 suite", Tags=[{"TagKey": "suite", "TagValue": "boto3"}])
    meta = made["KeyMetadata"]
    key = meta["KeyId"]
    arn = meta["Arn"]
    c.equal("CreateKey KeySpec", meta["KeySpec"], "SYMMETRIC_DEFAULT")
    c.equal("CreateKey KeyUsage", meta["KeyUsage"], "ENCRYPT_DECRYPT")
    c.that("CreateKey ARN", arn == f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{key}", arn)
    c.equal("DescribeKey on another member", kms().describe_key(KeyId=key)["KeyMetadata"]["Arn"], arn)

    kms().create_alias(AliasName="alias/clients-boto3", TargetKeyId=key)
    aliases = [a["AliasName"] for a in kms().list_aliases(KeyId=key)["Aliases"]]
    c.that("ListAliases names the alias", "alias/clients-boto3" in aliases, str(aliases))
    c.equal("DescribeKey by alias", kms().describe_key(KeyId="alias/clients-boto3")["KeyMetadata"]["KeyId"], key)
    c.raises("CreateAlias without alias/", "ValidationException",
             lambda: kms().create_alias(AliasName="nope", TargetKeyId=key))

    context = {"purpose": "suite", "tenant": "t1"}
    blob = kms().encrypt(KeyId="alias/clients-boto3", Plaintext=b"hunter2", EncryptionContext=context)["CiphertextBlob"]
    opened = kms().decrypt(CiphertextBlob=blob, EncryptionContext=context)
    c.equal("Decrypt plaintext", opened["Plaintext"], b"hunter2")
    c.equal("Decrypt names the key", opened["KeyId"], arn)
    c.equal("Decrypt EncryptionAlgorithm", opened["EncryptionAlgorithm"], "SYMMETRIC_DEFAULT")
    c.raises("Decrypt with another context", "InvalidCiphertextException",
             lambda: kms().decrypt(CiphertextBlob=blob, EncryptionContext={"purpose": "other"}))
    c.raises("Decrypt of garbage", "InvalidCiphertextException",
             lambda: kms().decrypt(CiphertextBlob=b"\x01" * 64))

    dk = kms().generate_data_key(KeyId=key, KeySpec="AES_256")
    c.equal("GenerateDataKey length", len(dk["Plaintext"]), 32)
    c.equal("GenerateDataKey blob opens", kms().decrypt(CiphertextBlob=dk["CiphertextBlob"])["Plaintext"], dk["Plaintext"])
    wo = kms().generate_data_key_without_plaintext(KeyId=key, NumberOfBytes=64)
    c.that("GenerateDataKeyWithoutPlaintext has no plaintext", "Plaintext" not in wo)
    c.equal("GenerateDataKeyWithoutPlaintext opens to 64 bytes",
            len(kms().decrypt(CiphertextBlob=wo["CiphertextBlob"])["Plaintext"]), 64)
    c.equal("GenerateRandom length", len(kms().generate_random(NumberOfBytes=48)["Plaintext"]), 48)

    other = kms().create_key(Description="re-encrypt target")["KeyMetadata"]
    moved = kms().re_encrypt(CiphertextBlob=blob, SourceEncryptionContext=context,
                             DestinationKeyId=other["KeyId"], DestinationEncryptionContext={"moved": "yes"})
    c.equal("ReEncrypt source key", moved["SourceKeyId"], arn)
    back = kms().decrypt(CiphertextBlob=moved["CiphertextBlob"], EncryptionContext={"moved": "yes"})
    c.equal("ReEncrypt result opens", (back["Plaintext"], back["KeyId"]), (b"hunter2", other["Arn"]))

    # -- Rotation, state, deletion ---------------------------------------------
    kms().enable_key_rotation(KeyId=key)
    c.equal("GetKeyRotationStatus", kms().get_key_rotation_status(KeyId=key)["KeyRotationEnabled"], True)
    kms().rotate_key_on_demand(KeyId=key)
    rotations = kms().list_key_rotations(KeyId=key)["Rotations"]
    c.that("ListKeyRotations after RotateKeyOnDemand", len(rotations) >= 1, str(rotations))
    c.equal("old ciphertext opens after rotation",
            kms().decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"], b"hunter2")
    kms().disable_key(KeyId=key)
    c.raises("Encrypt under a disabled key", "DisabledException",
             lambda: kms().encrypt(KeyId=key, Plaintext=b"x"))
    kms().enable_key(KeyId=key)
    c.equal("Encrypt after EnableKey", len(kms().encrypt(KeyId=key, Plaintext=b"x")["CiphertextBlob"]) > 0, True)
    gone = kms().create_key(Description="to delete")["KeyMetadata"]["KeyId"]
    sched = kms().schedule_key_deletion(KeyId=gone, PendingWindowInDays=7)
    c.equal("ScheduleKeyDeletion state", sched["KeyState"], "PendingDeletion")
    c.raises("Encrypt under a key pending deletion", "KMSInvalidStateException",
             lambda: kms().encrypt(KeyId=gone, Plaintext=b"x"))
    kms().cancel_key_deletion(KeyId=gone)
    c.equal("CancelKeyDeletion leaves it Disabled", kms().describe_key(KeyId=gone)["KeyMetadata"]["KeyState"], "Disabled")
    c.raises("DescribeKey of a missing key", "NotFoundException",
             lambda: kms().describe_key(KeyId=str(uuid.uuid4())))

    # -- Policies, grants, tags ------------------------------------------------
    c.equal("ListKeyPolicies", kms().list_key_policies(KeyId=key)["PolicyNames"], ["default"])
    policy = json.loads(kms().get_key_policy(KeyId=key, PolicyName="default")["Policy"])
    c.that("default policy trusts the account", ACCOUNT in json.dumps(policy), json.dumps(policy))
    policy["Statement"].append({"Sid": "Suite", "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/suite"},
                                "Action": "kms:Decrypt", "Resource": "*"})
    kms().put_key_policy(KeyId=key, PolicyName="default", Policy=json.dumps(policy))
    stored = json.loads(kms().get_key_policy(KeyId=key, PolicyName="default")["Policy"])
    c.that("PutKeyPolicy stored the statement", any(s.get("Sid") == "Suite" for s in stored["Statement"]))
    grant = kms().create_grant(KeyId=key, GranteePrincipal=f"arn:aws:iam::{ACCOUNT}:role/suite",
                               Operations=["Decrypt"], Name="suite-grant")
    grants = kms().list_grants(KeyId=key)["Grants"]
    c.that("ListGrants shows the grant", any(g["GrantId"] == grant["GrantId"] for g in grants), str(grants))
    kms().revoke_grant(KeyId=key, GrantId=grant["GrantId"])
    c.that("RevokeGrant removes it",
           all(g["GrantId"] != grant["GrantId"] for g in kms().list_grants(KeyId=key)["Grants"]))
    kms().tag_resource(KeyId=key, Tags=[{"TagKey": "team", "TagValue": "kms"}])
    tags = {t["TagKey"]: t["TagValue"] for t in kms().list_resource_tags(KeyId=key)["Tags"]}
    c.equal("ListResourceTags", tags, {"suite": "boto3", "team": "kms"})
    kms().untag_resource(KeyId=key, TagKeys=["team"])
    kms().update_key_description(KeyId=key, Description="renamed")
    c.equal("UpdateKeyDescription", kms().describe_key(KeyId=key)["KeyMetadata"]["Description"], "renamed")
    pages = list(kms().get_paginator("list_keys").paginate(PaginationConfig={"PageSize": 1}))
    listed = {k["KeyId"] for p in pages for k in p["Keys"]}
    c.that("ListKeys pages one key at a time", len(pages) >= 3 and key in listed, f"{len(pages)} pages")

    # -- Asymmetric and HMAC keys ----------------------------------------------
    rsa = kms().create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    message = b"sign this"
    sig = kms().sign(KeyId=rsa, Message=message, SigningAlgorithm="RSASSA_PSS_SHA_256")["Signature"]
    c.equal("Verify RSA-PSS", kms().verify(KeyId=rsa, Message=message, Signature=sig,
                                           SigningAlgorithm="RSASSA_PSS_SHA_256")["SignatureValid"], True)
    c.raises("Verify of another message", "KMSInvalidSignatureException",
             lambda: kms().verify(KeyId=rsa, Message=b"other", Signature=sig, SigningAlgorithm="RSASSA_PSS_SHA_256"))
    public = serialization.load_der_public_key(kms().get_public_key(KeyId=rsa)["PublicKey"])
    try:
        public.verify(sig, message, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
        c.that("RSA-PSS signature verifies locally", True)
    except Exception as e:  # noqa: BLE001
        c.that("RSA-PSS signature verifies locally", False, repr(e))

    ecc = kms().create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    sig = kms().sign(KeyId=ecc, Message=message, SigningAlgorithm="ECDSA_SHA_256")["Signature"]
    public = serialization.load_der_public_key(kms().get_public_key(KeyId=ecc)["PublicKey"])
    try:
        public.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        c.that("ECDSA signature verifies locally", True)
    except Exception as e:  # noqa: BLE001
        c.that("ECDSA signature verifies locally", False, repr(e))

    rsa_enc = kms().create_key(KeySpec="RSA_2048", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]["KeyId"]
    public = serialization.load_der_public_key(kms().get_public_key(KeyId=rsa_enc)["PublicKey"])
    # SHA-1: SoftHSM2, which stands in for the HSM in kms_node_cluster_test,
    # does OAEP with SHA-1 only.
    local = public.encrypt(b"sealed locally",
                           padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    c.equal("RSA-OAEP of a local encryption",
            kms().decrypt(KeyId=rsa_enc, CiphertextBlob=local, EncryptionAlgorithm="RSAES_OAEP_SHA_1")["Plaintext"],
            b"sealed locally")

    hmac = kms().create_key(KeySpec="HMAC_256", KeyUsage="GENERATE_VERIFY_MAC")["KeyMetadata"]["KeyId"]
    mac = kms().generate_mac(KeyId=hmac, Message=message, MacAlgorithm="HMAC_SHA_256")["Mac"]
    c.equal("VerifyMac", kms().verify_mac(KeyId=hmac, Message=message, Mac=mac,
                                          MacAlgorithm="HMAC_SHA_256")["MacValid"], True)
    c.raises("VerifyMac of another message", "KMSInvalidMacException",
             lambda: kms().verify_mac(KeyId=hmac, Message=b"other", Mac=mac, MacAlgorithm="HMAC_SHA_256"))

    pair = kms().generate_data_key_pair(KeyId=key, KeyPairSpec="ECC_NIST_P256")
    private = serialization.load_der_private_key(pair["PrivateKeyPlaintext"], None)
    wrapped = kms().decrypt(CiphertextBlob=pair["PrivateKeyCiphertextBlob"])["Plaintext"]
    c.equal("GenerateDataKeyPair private key opens", wrapped, pair["PrivateKeyPlaintext"])
    c.equal("GenerateDataKeyPair public key matches",
            private.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo),
            pair["PublicKey"])


def cli_suite(c: Checks, aws: str, endpoints: list[str], ca: str) -> None:
    # AWS_REGION outranks AWS_DEFAULT_REGION, and CI sets it for its build
    # cache (us-phoenix-1, which the cluster refuses as a SigV4 scope).
    env = dict(os.environ, AWS_CA_BUNDLE=ca, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
               AWS_PAGER="", AWS_EC2_METADATA_DISABLED="true")
    turn = [0]

    def run(*args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        endpoint = endpoints[turn[0] % len(endpoints)]
        turn[0] += 1
        p = subprocess.run([aws, "kms", *args, "--endpoint-url", endpoint, "--output", "json"],
                           env=env, capture_output=True, text=True, timeout=60)
        if ok and p.returncode != 0:
            raise RuntimeError(f"aws kms {' '.join(args)}: exit {p.returncode}: {p.stderr}")
        return p

    version = subprocess.run([aws, "--version"], capture_output=True, text=True, check=True)
    c.that("AWS CLI is v2", "aws-cli/2." in version.stdout + version.stderr, version.stdout)
    key = json.loads(run("create-key", "--description", "cli suite").stdout)["KeyMetadata"]["KeyId"]
    run("create-alias", "--alias-name", "alias/clients-cli", "--target-key-id", key)
    aliases = json.loads(run("list-aliases").stdout)["Aliases"]
    c.that("CLI list-aliases names the alias", any(a["AliasName"] == "alias/clients-cli" for a in aliases))
    with tempfile.TemporaryDirectory() as d:
        clear = os.path.join(d, "clear")
        sealed = os.path.join(d, "sealed")
        with open(clear, "wb") as f:
            f.write(b"through files")
        out = json.loads(run("encrypt", "--key-id", "alias/clients-cli", "--plaintext", f"fileb://{clear}",
                             "--encryption-context", "app=cli").stdout)
        with open(sealed, "wb") as f:
            f.write(base64.b64decode(out["CiphertextBlob"]))
        back = json.loads(run("decrypt", "--ciphertext-blob", f"fileb://{sealed}",
                              "--encryption-context", "app=cli").stdout)
        c.equal("CLI decrypt", base64.b64decode(back["Plaintext"]), b"through files")
    missing = run("describe-key", "--key-id", str(uuid.uuid4()), ok=False)
    c.that("CLI missing key exits non-zero with NotFoundException",
           missing.returncode != 0 and "NotFoundException" in missing.stderr, missing.stderr)


def esdk_suite(c: Checks, kms: Clients, endpoints: list[str], ca: str) -> None:
    # The SDK makes its own KMS clients; botocore takes the endpoint and the
    # CA bundle from the environment.
    os.environ["AWS_ENDPOINT_URL_KMS"] = endpoints[0]
    os.environ["AWS_CA_BUNDLE"] = ca
    import logging

    import aws_encryption_sdk
    from aws_encryption_sdk import CommitmentPolicy, StrictAwsKmsMasterKeyProvider

    # The refusal below is expected; the SDK logs its traceback.
    logging.getLogger("aws_encryption_sdk").setLevel(logging.CRITICAL)

    first = kms().create_key(Description="esdk one")["KeyMetadata"]["Arn"]
    second = kms().create_key(Description="esdk two")["KeyMetadata"]["Arn"]
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
    both = StrictAwsKmsMasterKeyProvider(key_ids=[first, second])
    context = {"order": "42"}
    message, header = client.encrypt(source=b"an encrypted message", key_provider=both,
                                     encryption_context=context)
    c.equal("ESDK message has a data key per KMS key", len(header.encrypted_data_keys), 2)
    only_second = StrictAwsKmsMasterKeyProvider(key_ids=[second])
    clear, dheader = client.decrypt(source=message, key_provider=only_second)
    c.equal("ESDK decrypt with one of the keys", clear, b"an encrypted message")
    c.equal("ESDK keeps the encryption context", dheader.encryption_context.get("order"), "42")
    stranger = kms().create_key(Description="esdk stranger")["KeyMetadata"]["Arn"]
    try:
        client.decrypt(source=message, key_provider=StrictAwsKmsMasterKeyProvider(key_ids=[stranger]))
        c.that("ESDK refuses a provider without the keys", False, "it decrypted")
    except Exception:  # noqa: BLE001 - the SDK's own error types vary by version
        c.that("ESDK refuses a provider without the keys", True)
    big = os.urandom(300_000)
    streamed, _ = client.encrypt(source=big, key_provider=both, frame_length=4096)
    c.equal("ESDK framed message round trips", client.decrypt(source=streamed, key_provider=both)[0], big)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--endpoints", required=True, help="comma-separated https URLs of KMS members")
    p.add_argument("--ca", required=True, help="CA bundle for the endpoints' certificates")
    p.add_argument("--aws", default=shutil.which("aws") or "", help="the AWS CLI v2 binary")
    p.add_argument("--skip", default="", help="comma-separated suites not to run: boto3, cli, esdk")
    args = p.parse_args()
    endpoints = [e for e in args.endpoints.split(",") if e]
    skip = {s for s in args.skip.split(",") if s}
    c = Checks()
    kms = Clients(endpoints, args.ca)
    if "boto3" not in skip:
        c.run("boto3", lambda: boto3_suite(c, kms))
    if "cli" not in skip:
        if not args.aws:
            c.that("AWS CLI v2 installed", False, "no aws on PATH; pass --aws or --skip cli")
        else:
            c.run("AWS CLI v2", lambda: cli_suite(c, args.aws, endpoints, args.ca))
    if "esdk" not in skip:
        c.run("AWS Encryption SDK", lambda: esdk_suite(c, kms, endpoints, args.ca))
    print(f"{c.passed} checks passed, {len(c.failed)} failed", flush=True)
    for f in c.failed:
        print(f"  {f}")
    return 0 if not c.failed else 1


if __name__ == "__main__":
    sys.exit(main())
