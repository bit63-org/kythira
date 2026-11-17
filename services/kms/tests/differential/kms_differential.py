#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Differential test of Kythira's KMS API against recordings of AWS KMS.

.kiro/specs/kms-compatible-api/ task 18 (Requirement 14.3): request
validation and errors for every operation, compared with real AWS KMS. A
fixed list of cases is run once against AWS and the normalised answers are
written to a recording; CI runs the same list against kms_node and compares
case by case.

    kms_differential.py run --real-aws --out FILE [--region R]
    kms_differential.py run --endpoint URL --out FILE [--ca FILE]
    kms_differential.py compare --endpoint URL --recording FILE [--allow FILE] [--ca FILE]

What is compared is what a client branches on, never ciphertexts:

  * an error as its type (`__type`, e.g. NotFoundException) and HTTP status;
    its message only with --strict-messages, and otherwise as a note;
  * a success as the set of top-level fields in the answer and the values
    that do not vary between services or runs (key spec, usage, state,
    algorithms, SignatureValid and so on). Blobs, ids, ARNs, dates and
    list contents are placeholders, since an AWS account holds other keys.

botocore's own parameter validation is off, so a malformed request reaches
the service and the service's answer is what gets recorded.

A run makes four keys (symmetric, RSA_2048 signing, HMAC_256, and a
symmetric key it disables and schedules for deletion), one alias and a
grant. However the run ends it deletes the alias and schedules every key it
made for deletion after the shortest window AWS allows (7 days). On AWS that
costs about $1 a month per key, prorated by the hour: under $1 for a run.
--real-aws uses the ambient credentials (AWS_PROFILE and so on) and needs
Clark's go each time.
"""

import argparse
import json
import os
import re
import sys
import time
import uuid

TOOL_VERSION = 1
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MRK_RE = re.compile(r"mrk-[0-9a-f]{32}")
ACCOUNT_RE = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
# Values worth comparing where they appear in a successful answer: each is
# fixed by the request, not by the service or the run.
KEPT = {
    "KeySpec", "KeyUsage", "KeyState", "Enabled", "KeyManager", "Origin",
    "MultiRegion", "EncryptionAlgorithms", "SigningAlgorithms", "MacAlgorithms",
    "CustomerMasterKeySpec", "KeyRotationEnabled", "RotationPeriodInDays",
    "SignatureValid", "MacValid", "EncryptionAlgorithm", "SigningAlgorithm",
    "MacAlgorithm", "KeyPairSpec", "PolicyNames", "Truncated",
    "SourceEncryptionAlgorithm", "DestinationEncryptionAlgorithm",
}
# Blobs whose length is fixed by the request.
SIZED = {"Plaintext"}
MISSING = "00000000-0000-4000-8000-000000000000"  # no account has this key


# ---- the cases -----------------------------------------------------------
#
# A case is (name, operation, request). In a request, "$K1".."$K4" stand for
# the run's keys (their ids), "$K1.arn" for an ARN, "$ALIAS" for the run's
# alias, "$CT1" for a ciphertext of K1 made under context {"purpose":"diff"},
# "$SIG2" for K2's signature of b"message", "$MAC3" for K3's MAC of b"message",
# "$GRANT" / "$GRANTTOKEN" for the run's grant. "b:..." is a blob (UTF-8),
# "n:N" a blob of N zero bytes. Setup cases record like any other.

KEY_SETUP = [
    ("create symmetric key", "CreateKey", {"Description": "kythira differential K1"}),
    ("create rsa signing key", "CreateKey",
     {"Description": "kythira differential K2", "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}),
    ("create hmac key", "CreateKey",
     {"Description": "kythira differential K3", "KeySpec": "HMAC_256",
      "KeyUsage": "GENERATE_VERIFY_MAC"}),
    ("create victim key", "CreateKey", {"Description": "kythira differential K4"}),
]

CASES = [
    # CreateKey: only refusals, a key that is made costs money.
    ("createkey unknown key spec", "CreateKey", {"KeySpec": "NOPE_1"}),
    ("createkey signing usage on symmetric", "CreateKey",
     {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "SIGN_VERIFY"}),
    ("createkey hmac without mac usage", "CreateKey", {"KeySpec": "HMAC_256"}),
    ("createkey policy not json", "CreateKey", {"Policy": "not a policy"}),
    ("createkey description too long", "CreateKey", {"Description": "d" * 8193}),
    ("createkey unknown origin", "CreateKey", {"Origin": "BOGUS"}),
    ("createkey bad tag", "CreateKey", {"Tags": [{"TagKey": "aws:reserved", "TagValue": "x"}]}),

    # DescribeKey
    ("describekey no key id", "DescribeKey", {}),
    ("describekey empty key id", "DescribeKey", {"KeyId": ""}),
    ("describekey missing key", "DescribeKey", {"KeyId": MISSING}),
    ("describekey missing alias", "DescribeKey", {"KeyId": "alias/kythira-diff-absent"}),
    ("describekey malformed arn", "DescribeKey", {"KeyId": "arn:aws:kms:nowhere"}),
    ("describekey symmetric", "DescribeKey", {"KeyId": "$K1"}),
    ("describekey by arn", "DescribeKey", {"KeyId": "$K2.arn"}),
    ("describekey hmac", "DescribeKey", {"KeyId": "$K3"}),

    # ListKeys
    ("listkeys limit zero", "ListKeys", {"Limit": 0}),
    ("listkeys limit too big", "ListKeys", {"Limit": 1001}),
    ("listkeys bad marker", "ListKeys", {"Marker": "not-a-marker"}),
    ("listkeys one", "ListKeys", {"Limit": 1}),

    # Encrypt
    ("encrypt empty plaintext", "Encrypt", {"KeyId": "$K1", "Plaintext": "n:0"}),
    ("encrypt plaintext too big", "Encrypt", {"KeyId": "$K1", "Plaintext": "n:4097"}),
    ("encrypt with signing key", "Encrypt", {"KeyId": "$K2", "Plaintext": "b:secret"}),
    ("encrypt with hmac key", "Encrypt", {"KeyId": "$K3", "Plaintext": "b:secret"}),
    ("encrypt rsa algorithm on symmetric", "Encrypt",
     {"KeyId": "$K1", "Plaintext": "b:secret", "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}),
    ("encrypt unknown algorithm", "Encrypt",
     {"KeyId": "$K1", "Plaintext": "b:secret", "EncryptionAlgorithm": "ROT13"}),
    ("encrypt missing key", "Encrypt", {"KeyId": MISSING, "Plaintext": "b:secret"}),
    ("encrypt no key id", "Encrypt", {"Plaintext": "b:secret"}),
    ("encrypt with context", "Encrypt",
     {"KeyId": "$K1", "Plaintext": "b:secret", "EncryptionContext": {"purpose": "diff"}}),

    # Decrypt
    ("decrypt garbage", "Decrypt", {"CiphertextBlob": "b:not a ciphertext at all"}),
    ("decrypt empty blob", "Decrypt", {"CiphertextBlob": "n:0"}),
    ("decrypt wrong context", "Decrypt",
     {"CiphertextBlob": "$CT1", "EncryptionContext": {"purpose": "other"}}),
    ("decrypt no context", "Decrypt", {"CiphertextBlob": "$CT1"}),
    ("decrypt names another key", "Decrypt",
     {"CiphertextBlob": "$CT1", "EncryptionContext": {"purpose": "diff"}, "KeyId": "$K4"}),
    ("decrypt rsa algorithm", "Decrypt",
     {"CiphertextBlob": "$CT1", "EncryptionContext": {"purpose": "diff"},
      "EncryptionAlgorithm": "RSAES_OAEP_SHA_1"}),
    ("decrypt", "Decrypt",
     {"CiphertextBlob": "$CT1", "EncryptionContext": {"purpose": "diff"}}),
    ("decrypt naming the key", "Decrypt",
     {"CiphertextBlob": "$CT1", "EncryptionContext": {"purpose": "diff"}, "KeyId": "$K1.arn"}),

    # ReEncrypt
    ("reencrypt garbage", "ReEncrypt",
     {"CiphertextBlob": "b:not a ciphertext at all", "DestinationKeyId": "$K1"}),
    ("reencrypt to signing key", "ReEncrypt",
     {"CiphertextBlob": "$CT1", "SourceEncryptionContext": {"purpose": "diff"},
      "DestinationKeyId": "$K2"}),
    ("reencrypt no destination", "ReEncrypt",
     {"CiphertextBlob": "$CT1", "SourceEncryptionContext": {"purpose": "diff"}}),
    ("reencrypt", "ReEncrypt",
     {"CiphertextBlob": "$CT1", "SourceEncryptionContext": {"purpose": "diff"},
      "DestinationKeyId": "$K1", "DestinationEncryptionContext": {"purpose": "again"}}),

    # GenerateDataKey and friends
    ("generatedatakey no size", "GenerateDataKey", {"KeyId": "$K1"}),
    ("generatedatakey spec and bytes", "GenerateDataKey",
     {"KeyId": "$K1", "KeySpec": "AES_256", "NumberOfBytes": 32}),
    ("generatedatakey zero bytes", "GenerateDataKey", {"KeyId": "$K1", "NumberOfBytes": 0}),
    ("generatedatakey too many bytes", "GenerateDataKey",
     {"KeyId": "$K1", "NumberOfBytes": 1025}),
    ("generatedatakey unknown spec", "GenerateDataKey", {"KeyId": "$K1", "KeySpec": "AES_512"}),
    ("generatedatakey signing key", "GenerateDataKey", {"KeyId": "$K2", "KeySpec": "AES_256"}),
    ("generatedatakey missing key", "GenerateDataKey",
     {"KeyId": MISSING, "KeySpec": "AES_256"}),
    ("generatedatakey aes 128", "GenerateDataKey", {"KeyId": "$K1", "KeySpec": "AES_128"}),
    ("generatedatakey 64 bytes", "GenerateDataKey", {"KeyId": "$K1", "NumberOfBytes": 64}),
    ("generatedatakeywithoutplaintext no size", "GenerateDataKeyWithoutPlaintext",
     {"KeyId": "$K1"}),
    ("generatedatakeywithoutplaintext", "GenerateDataKeyWithoutPlaintext",
     {"KeyId": "$K1", "KeySpec": "AES_256"}),
    ("generatedatakeypair unknown spec", "GenerateDataKeyPair",
     {"KeyId": "$K1", "KeyPairSpec": "RSA_1024"}),
    ("generatedatakeypair signing key", "GenerateDataKeyPair",
     {"KeyId": "$K2", "KeyPairSpec": "ECC_NIST_P256"}),
    ("generatedatakeypair", "GenerateDataKeyPair",
     {"KeyId": "$K1", "KeyPairSpec": "ECC_NIST_P256"}),
    ("generatedatakeypairwithoutplaintext", "GenerateDataKeyPairWithoutPlaintext",
     {"KeyId": "$K1", "KeyPairSpec": "ECC_NIST_P384"}),

    # GenerateRandom
    ("generaterandom zero", "GenerateRandom", {"NumberOfBytes": 0}),
    ("generaterandom too many", "GenerateRandom", {"NumberOfBytes": 1025}),
    ("generaterandom", "GenerateRandom", {"NumberOfBytes": 32}),

    # Sign and Verify
    ("sign with symmetric key", "Sign",
     {"KeyId": "$K1", "Message": "b:message", "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("sign ecdsa on rsa", "Sign",
     {"KeyId": "$K2", "Message": "b:message", "SigningAlgorithm": "ECDSA_SHA_256"}),
    ("sign unknown algorithm", "Sign",
     {"KeyId": "$K2", "Message": "b:message", "SigningAlgorithm": "RSA_MD5"}),
    ("sign message too big", "Sign",
     {"KeyId": "$K2", "Message": "n:4097", "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("sign digest of wrong length", "Sign",
     {"KeyId": "$K2", "Message": "n:20", "MessageType": "DIGEST",
      "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("sign no algorithm", "Sign", {"KeyId": "$K2", "Message": "b:message"}),
    ("sign", "Sign",
     {"KeyId": "$K2", "Message": "b:message", "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("verify wrong signature", "Verify",
     {"KeyId": "$K2", "Message": "b:message", "Signature": "n:256",
      "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("verify other message", "Verify",
     {"KeyId": "$K2", "Message": "b:other", "Signature": "$SIG2",
      "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),
    ("verify", "Verify",
     {"KeyId": "$K2", "Message": "b:message", "Signature": "$SIG2",
      "SigningAlgorithm": "RSASSA_PSS_SHA_256"}),

    # GenerateMac and VerifyMac
    ("generatemac with symmetric key", "GenerateMac",
     {"KeyId": "$K1", "Message": "b:message", "MacAlgorithm": "HMAC_SHA_256"}),
    ("generatemac other algorithm", "GenerateMac",
     {"KeyId": "$K3", "Message": "b:message", "MacAlgorithm": "HMAC_SHA_384"}),
    ("generatemac empty message", "GenerateMac",
     {"KeyId": "$K3", "Message": "n:0", "MacAlgorithm": "HMAC_SHA_256"}),
    ("generatemac", "GenerateMac",
     {"KeyId": "$K3", "Message": "b:message", "MacAlgorithm": "HMAC_SHA_256"}),
    ("verifymac wrong mac", "VerifyMac",
     {"KeyId": "$K3", "Message": "b:message", "Mac": "n:32", "MacAlgorithm": "HMAC_SHA_256"}),
    ("verifymac", "VerifyMac",
     {"KeyId": "$K3", "Message": "b:message", "Mac": "$MAC3", "MacAlgorithm": "HMAC_SHA_256"}),

    # GetPublicKey
    ("getpublickey symmetric", "GetPublicKey", {"KeyId": "$K1"}),
    ("getpublickey hmac", "GetPublicKey", {"KeyId": "$K3"}),
    ("getpublickey", "GetPublicKey", {"KeyId": "$K2"}),

    # Aliases
    ("createalias without prefix", "CreateAlias",
     {"AliasName": "kythira-diff", "TargetKeyId": "$K1"}),
    ("createalias reserved prefix", "CreateAlias",
     {"AliasName": "alias/aws/kythira-diff", "TargetKeyId": "$K1"}),
    ("createalias bad characters", "CreateAlias",
     {"AliasName": "alias/no spaces!", "TargetKeyId": "$K1"}),
    ("createalias missing target", "CreateAlias", {"AliasName": "$ALIAS", "TargetKeyId": MISSING}),
    ("createalias to an alias", "CreateAlias",
     {"AliasName": "$ALIAS", "TargetKeyId": "alias/kythira-diff-absent"}),
    ("createalias", "CreateAlias", {"AliasName": "$ALIAS", "TargetKeyId": "$K1"}),
    ("createalias again", "CreateAlias", {"AliasName": "$ALIAS", "TargetKeyId": "$K4"}),
    ("describekey by alias", "DescribeKey", {"KeyId": "$ALIAS"}),
    ("updatealias missing alias", "UpdateAlias",
     {"AliasName": "alias/kythira-diff-absent", "TargetKeyId": "$K1"}),
    ("updatealias to signing key", "UpdateAlias", {"AliasName": "$ALIAS", "TargetKeyId": "$K2"}),
    ("updatealias", "UpdateAlias", {"AliasName": "$ALIAS", "TargetKeyId": "$K4"}),
    ("listaliases missing key", "ListAliases", {"KeyId": MISSING}),
    ("listaliases limit zero", "ListAliases", {"Limit": 0}),
    ("listaliases for key", "ListAliases", {"KeyId": "$K4"}),
    ("deletealias missing", "DeleteAlias", {"AliasName": "alias/kythira-diff-absent"}),
    ("deletealias without prefix", "DeleteAlias", {"AliasName": "kythira-diff"}),

    # Enable and disable
    ("disablekey missing key", "DisableKey", {"KeyId": MISSING}),
    ("enablekey missing key", "EnableKey", {"KeyId": MISSING}),
    ("disablekey", "DisableKey", {"KeyId": "$K4"}),
    ("describekey disabled", "DescribeKey", {"KeyId": "$K4"}),
    ("encrypt disabled", "Encrypt", {"KeyId": "$K4", "Plaintext": "b:secret"}),
    ("generatedatakey disabled", "GenerateDataKey", {"KeyId": "$K4", "KeySpec": "AES_256"}),
    ("encrypt through alias of disabled", "Encrypt", {"KeyId": "$ALIAS", "Plaintext": "b:secret"}),
    ("enablekey", "EnableKey", {"KeyId": "$K4"}),

    # Rotation
    ("enablekeyrotation signing key", "EnableKeyRotation", {"KeyId": "$K2"}),
    ("enablekeyrotation hmac key", "EnableKeyRotation", {"KeyId": "$K3"}),
    ("enablekeyrotation period too short", "EnableKeyRotation",
     {"KeyId": "$K1", "RotationPeriodInDays": 5}),
    ("enablekeyrotation period too long", "EnableKeyRotation",
     {"KeyId": "$K1", "RotationPeriodInDays": 2561}),
    ("getkeyrotationstatus before", "GetKeyRotationStatus", {"KeyId": "$K1"}),
    ("enablekeyrotation", "EnableKeyRotation", {"KeyId": "$K1", "RotationPeriodInDays": 90}),
    ("getkeyrotationstatus after", "GetKeyRotationStatus", {"KeyId": "$K1"}),
    ("getkeyrotationstatus signing key", "GetKeyRotationStatus", {"KeyId": "$K2"}),
    ("disablekeyrotation signing key", "DisableKeyRotation", {"KeyId": "$K2"}),
    ("disablekeyrotation", "DisableKeyRotation", {"KeyId": "$K1"}),
    ("rotatekeyondemand signing key", "RotateKeyOnDemand", {"KeyId": "$K2"}),
    ("listkeyrotations signing key", "ListKeyRotations", {"KeyId": "$K2"}),
    ("listkeyrotations", "ListKeyRotations", {"KeyId": "$K1"}),

    # Key policies
    ("getkeypolicy other name", "GetKeyPolicy", {"KeyId": "$K1", "PolicyName": "other"}),
    ("getkeypolicy", "GetKeyPolicy", {"KeyId": "$K1", "PolicyName": "default"}),
    ("listkeypolicies", "ListKeyPolicies", {"KeyId": "$K1"}),
    ("putkeypolicy not json", "PutKeyPolicy",
     {"KeyId": "$K1", "PolicyName": "default", "Policy": "{"}),
    ("putkeypolicy other name", "PutKeyPolicy",
     {"KeyId": "$K1", "PolicyName": "other", "Policy": "$POLICY"}),
    ("putkeypolicy no statement", "PutKeyPolicy",
     {"KeyId": "$K1", "PolicyName": "default", "Policy": '{"Version":"2012-10-17"}'}),
    ("putkeypolicy", "PutKeyPolicy",
     {"KeyId": "$K1", "PolicyName": "default", "Policy": "$POLICY"}),

    # Grants
    ("creategrant unknown operation", "CreateGrant",
     {"KeyId": "$K1", "GranteePrincipal": "$ROOT", "Operations": ["Bogus"]}),
    ("creategrant no operations", "CreateGrant",
     {"KeyId": "$K1", "GranteePrincipal": "$ROOT", "Operations": []}),
    ("creategrant sign on symmetric", "CreateGrant",
     {"KeyId": "$K1", "GranteePrincipal": "$ROOT", "Operations": ["Sign"]}),
    ("creategrant missing key", "CreateGrant",
     {"KeyId": MISSING, "GranteePrincipal": "$ROOT", "Operations": ["Decrypt"]}),
    ("creategrant", "CreateGrant",
     {"KeyId": "$K1", "GranteePrincipal": "$ROOT", "Operations": ["Decrypt", "Encrypt"],
      "Name": "kythira-diff"}),
    ("listgrants limit zero", "ListGrants", {"KeyId": "$K1", "Limit": 0}),
    ("listgrants", "ListGrants", {"KeyId": "$K1"}),
    ("listgrants missing key", "ListGrants", {"KeyId": MISSING}),
    ("listretirablegrants bad principal", "ListRetirableGrants",
     {"RetiringPrincipal": "not an arn"}),
    ("listretirablegrants limit zero", "ListRetirableGrants",
     {"RetiringPrincipal": "$ROOT", "Limit": 0}),
    ("listretirablegrants", "ListRetirableGrants", {"RetiringPrincipal": "$ROOT"}),
    ("retiregrant bad token", "RetireGrant", {"GrantToken": "not-a-grant-token"}),
    ("revokegrant missing grant", "RevokeGrant", {"KeyId": "$K1", "GrantId": "0" * 64}),
    ("revokegrant", "RevokeGrant", {"KeyId": "$K1", "GrantId": "$GRANT"}),

    # Tags and description
    ("tagresource reserved key", "TagResource",
     {"KeyId": "$K1", "Tags": [{"TagKey": "aws:x", "TagValue": "y"}]}),
    ("tagresource empty key", "TagResource",
     {"KeyId": "$K1", "Tags": [{"TagKey": "", "TagValue": "y"}]}),
    ("tagresource", "TagResource",
     {"KeyId": "$K1", "Tags": [{"TagKey": "team", "TagValue": "kythira"}]}),
    ("listresourcetags", "ListResourceTags", {"KeyId": "$K1"}),
    ("untagresource", "UntagResource", {"KeyId": "$K1", "TagKeys": ["team"]}),
    ("updatekeydescription missing key", "UpdateKeyDescription",
     {"KeyId": MISSING, "Description": "x"}),
    ("updatekeydescription", "UpdateKeyDescription",
     {"KeyId": "$K1", "Description": "kythira differential K1, described again"}),

    # Deletion
    ("schedulekeydeletion window too short", "ScheduleKeyDeletion",
     {"KeyId": "$K4", "PendingWindowInDays": 6}),
    ("schedulekeydeletion window too long", "ScheduleKeyDeletion",
     {"KeyId": "$K4", "PendingWindowInDays": 31}),
    ("schedulekeydeletion missing key", "ScheduleKeyDeletion", {"KeyId": MISSING}),
    ("cancelkeydeletion not pending", "CancelKeyDeletion", {"KeyId": "$K4"}),
    ("schedulekeydeletion", "ScheduleKeyDeletion", {"KeyId": "$K4", "PendingWindowInDays": 7}),
    ("describekey pending deletion", "DescribeKey", {"KeyId": "$K4"}),
    ("encrypt pending deletion", "Encrypt", {"KeyId": "$K4", "Plaintext": "b:secret"}),
    ("enablekey pending deletion", "EnableKey", {"KeyId": "$K4"}),
    ("schedulekeydeletion again", "ScheduleKeyDeletion",
     {"KeyId": "$K4", "PendingWindowInDays": 7}),
    ("cancelkeydeletion", "CancelKeyDeletion", {"KeyId": "$K4"}),
    ("describekey after cancel", "DescribeKey", {"KeyId": "$K4"}),
    ("deletealias", "DeleteAlias", {"AliasName": "$ALIAS"}),
    ("deletealias again", "DeleteAlias", {"AliasName": "$ALIAS"}),
]


# ---- normalising ---------------------------------------------------------


class Normaliser:
    """Makes one run's answers comparable with another's."""

    def __init__(self, region):
        self.region = region
        self.names = {}  # concrete -> symbolic

    def learn(self, concrete, symbolic):
        if concrete:
            self.names[concrete] = symbolic

    def text(self, s):
        for concrete, symbolic in sorted(self.names.items(), key=lambda kv: -len(kv[0])):
            s = s.replace(concrete, symbolic)
        s = UUID_RE.sub("<uuid>", s)
        s = MRK_RE.sub("<mrk>", s)
        s = ACCOUNT_RE.sub("ACCOUNT", s)
        return s.replace(":" + self.region + ":", ":REGION:")

    def success(self, response):
        out = {"fields": sorted(k for k in response if k != "ResponseMetadata")}
        for k, v in response.items():
            if k in KEPT:
                out[k] = v
            elif k in SIZED and isinstance(v, (bytes, bytearray)):
                out[k] = "<bytes:%d>" % len(v)
        md = response.get("KeyMetadata")
        if isinstance(md, dict):
            out["KeyMetadata"] = {k: v for k, v in md.items() if k in KEPT}
        return out

    def error(self, err, status):
        return {"error": err.get("Code", ""), "status": status,
                "message": self.text(err.get("Message", ""))}


# ---- running the cases ---------------------------------------------------


class Run:
    """The cases against one service, recorded as normalised steps."""

    def __init__(self, client, region, pace=0.25):
        self.client = client
        # AWS's CreateKey quota is 5 requests a second (kms_node applies the
        # same quotas); pacing keeps every call clear of ThrottlingException.
        self.pace = pace
        self.norm = Normaliser(region)
        self.vars = {}
        self.alias = "alias/kythira-diff-" + uuid.uuid4().hex[:12]
        self.norm.learn(self.alias, "alias/kythira-diff-RUN")
        self.vars["$ALIAS"] = self.alias
        self.made = []
        self.steps = []

    # A symbolic request made concrete.
    def resolve(self, v):
        if isinstance(v, dict):
            return {k: self.resolve(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.resolve(x) for x in v]
        if not isinstance(v, str):
            return v
        if v.startswith("b:"):
            return v[2:].encode()
        if v.startswith("n:"):
            return bytes(int(v[2:]))
        if v in self.vars:
            return self.vars[v]
        return v

    def call(self, name, op, request):
        from botocore.exceptions import ClientError

        time.sleep(self.pace)
        method = getattr(self.client, re.sub(r"(?<!^)(?=[A-Z])", "_", op).lower())
        try:
            response = method(**self.resolve(request))
            if op == "CreateKey":
                self.made.append(response["KeyMetadata"]["KeyId"])
            step = {"case": name, "op": op, "request": request,
                    "response": self.norm.success(response)}
        except ClientError as e:
            status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            response = None
            step = {"case": name, "op": op, "request": request,
                    "response": self.norm.error(e.response.get("Error", {}), status)}
        self.steps.append(step)
        return response

    def setup(self):
        for i, (name, op, request) in enumerate(KEY_SETUP, start=1):
            r = self.call(name, op, request)
            if r is None:
                raise SystemExit("setup failed at %r: %s" % (name, self.steps[-1]["response"]))
            md = r["KeyMetadata"]
            self.vars["$K%d" % i] = md["KeyId"]
            self.vars["$K%d.arn" % i] = md["Arn"]
            self.norm.learn(md["Arn"], "$K%d.arn" % i)
            self.norm.learn(md["KeyId"], "$K%d" % i)
            account = md["Arn"].split(":")[4]
            self.vars["$ROOT"] = "arn:aws:iam::%s:root" % account
            self.vars["$POLICY"] = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Sid": "root", "Effect": "Allow",
                               "Principal": {"AWS": self.vars["$ROOT"]},
                               "Action": "kms:*", "Resource": "*"}]})
        # Blobs later cases use; not recorded, their answers are blobs.
        c = self.client
        self.vars["$CT1"] = c.encrypt(KeyId=self.vars["$K1"], Plaintext=b"secret",
                                      EncryptionContext={"purpose": "diff"})["CiphertextBlob"]
        self.vars["$SIG2"] = c.sign(KeyId=self.vars["$K2"], Message=b"message",
                                    SigningAlgorithm="RSASSA_PSS_SHA_256")["Signature"]
        self.vars["$MAC3"] = c.generate_mac(KeyId=self.vars["$K3"], Message=b"message",
                                            MacAlgorithm="HMAC_SHA_256")["Mac"]

    def run(self):
        try:
            self.setup()
            for name, op, request in CASES:
                r = self.call(name, op, request)
                if op == "CreateGrant" and r is not None:
                    self.vars["$GRANT"] = r["GrantId"]
                    self.norm.learn(r["GrantId"], "$GRANT")
                    self.norm.learn(r.get("GrantToken", ""), "$GRANTTOKEN")
            return self.steps
        finally:
            self.cleanup()

    def cleanup(self):
        """Deletes what the run made, whatever happened."""
        try:
            self.client.delete_alias(AliasName=self.alias)
        except Exception:  # noqa: BLE001 - it may never have been made
            pass
        for key in self.made:
            try:
                self.client.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
            except Exception as e:  # noqa: BLE001 - report and go on
                if "pending deletion" not in str(e).lower():
                    print("cleanup: %s: %s" % (key, e), file=sys.stderr)


# ---- comparing -----------------------------------------------------------


def diff(a, b, path=""):
    """Paths where `a` (the recording) and `b` differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            p = path + "." + k if path else k
            if k not in a:
                out.append((p, "<absent>", b[k]))
            elif k not in b:
                out.append((p, a[k], "<absent>"))
            else:
                out += diff(a[k], b[k], p)
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, "%s[%d]" % (path, i))
        return out
    return [] if a == b else [(path, a, b)]


def compare(recorded, got, allow=(), strict_messages=False):
    """(failures, notes) comparing two step lists case by case."""
    failures, notes = [], []
    allowed = {(x["case"], x["path"]) for x in allow}
    by_case = {s["case"]: s for s in got}
    for a in recorded:
        b = by_case.get(a["case"])
        where = "%s (%s)" % (a["case"], a["op"])
        if b is None:
            failures.append(where + ": not run")
            continue
        if a["op"] != b["op"] or a["request"] != b["request"]:
            failures.append(where + ": the request differs from the recording's")
            continue
        for path, x, y in diff(a["response"], b["response"]):
            line = "%s: %s recorded %s, got %s" % (
                where, path, json.dumps(x)[:160], json.dumps(y)[:160])
            if (a["case"], path) in allowed:
                notes.append("allowed " + line)
            elif path == "message" and not strict_messages:
                notes.append(line)
            else:
                failures.append(line)
    extra = set(by_case) - {s["case"] for s in recorded}
    for case in sorted(extra):
        failures.append(case + ": not in the recording")
    return failures, notes


# ---- the command line ----------------------------------------------------


def make_client(endpoint, region, ca=None):
    import boto3
    from botocore.config import Config

    cfg = Config(retries={"max_attempts": 1}, parameter_validation=False,
                 connect_timeout=5, read_timeout=30)
    kw = {"region_name": region, "config": cfg}
    if endpoint:
        kw["endpoint_url"] = endpoint
    if ca:
        kw["verify"] = ca
    return boto3.client("kms", **kw)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--endpoint")
    r.add_argument("--real-aws", action="store_true")
    r.add_argument("--region", default="us-east-1")
    r.add_argument("--ca")
    r.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--endpoint", required=True)
    c.add_argument("--region", default="us-east-1")
    c.add_argument("--ca")
    c.add_argument("--recording", required=True)
    c.add_argument("--allow")
    c.add_argument("--strict-messages", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "run":
        if bool(a.endpoint) == a.real_aws:
            p.error("give exactly one of --endpoint or --real-aws")
        # Before the run: a run against AWS costs money, and its answers
        # must have somewhere to go.
        if os.path.dirname(a.out):
            os.makedirs(os.path.dirname(a.out), exist_ok=True)
        steps = Run(make_client(a.endpoint, a.region, a.ca), a.region).run()
        import botocore

        rec = {"version": TOOL_VERSION, "target": "aws" if a.real_aws else "endpoint",
               "region": a.region, "botocore": botocore.__version__,
               "recorded_at": int(time.time()), "steps": steps}
        with open(a.out, "w") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
            f.write("\n")
        print(json.dumps({"steps": len(steps), "out": a.out}))
        return 0

    with open(a.recording) as f:
        rec = json.load(f)
    allow = []
    if a.allow:
        with open(a.allow) as f:
            allow = json.load(f)
    got = Run(make_client(a.endpoint, rec["region"], a.ca), rec["region"]).run()
    failures, notes = compare(rec["steps"], got, allow, a.strict_messages)
    for n in notes:
        print("note: " + n)
    for f in failures:
        print("FAIL: " + f, file=sys.stderr)
    print(json.dumps({"failures": len(failures), "notes": len(notes)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
