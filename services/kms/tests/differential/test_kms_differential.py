#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Offline checks of kms_differential.py: the case list, the normaliser and
the comparison. No boto3 and no network."""

import importlib.util
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("kms_differential",
                                              os.path.join(HERE, "kms_differential.py"))
kd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kd)

KNOWN_VARS = {"$ALIAS", "$CT1", "$SIG2", "$MAC3", "$GRANT", "$ROOT", "$POLICY"} | {
    "$K%d" % i for i in range(1, 5)} | {"$K%d.arn" % i for i in range(1, 5)}


def strings(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)
    elif isinstance(v, str):
        yield v


class CaseList(unittest.TestCase):
    def test_names_are_unique(self):
        names = [c[0] for c in kd.KEY_SETUP + kd.CASES]
        self.assertEqual(len(names), len(set(names)))

    def test_every_variable_is_one_the_run_defines(self):
        for name, _, request in kd.KEY_SETUP + kd.CASES:
            for s in strings(request):
                if s.startswith("$"):
                    self.assertIn(s, KNOWN_VARS, name)

    def test_operations_are_aws_names(self):
        for name, op, _ in kd.CASES:
            self.assertRegex(op, r"^[A-Z][A-Za-z]+$", name)

    def test_setup_makes_four_keys_and_cases_make_none_on_purpose(self):
        self.assertEqual([op for _, op, _ in kd.KEY_SETUP], ["CreateKey"] * 4)
        for name, op, request in kd.CASES:
            if op == "CreateKey":
                # Each CreateKey case must carry something AWS refuses.
                self.assertTrue(set(request) & {"KeySpec", "KeyUsage", "Policy", "Description",
                                                "Origin", "Tags"}, name)

    def test_every_implemented_operation_has_a_case(self):
        listed = os.path.join(HERE, "..", "..", "implemented-operations.txt")
        with open(listed) as f:
            implemented = {line.strip() for line in f
                           if line.strip() and not line.startswith("#")}
        self.assertEqual(implemented - {op for _, op, _ in kd.CASES}, set())

    def test_rarely_tested_operations_are_covered(self):
        ops = {op for _, op, _ in kd.CASES}
        for op in ("ReEncrypt", "GenerateDataKeyPair", "VerifyMac", "RetireGrant",
                   "RotateKeyOnDemand", "CancelKeyDeletion", "PutKeyPolicy"):
            self.assertIn(op, ops)


class Normalising(unittest.TestCase):
    def setUp(self):
        self.n = kd.Normaliser("us-east-1")
        self.id = "1234abcd-12ab-34cd-56ef-1234567890ab"
        self.arn = "arn:aws:kms:us-east-1:827617851594:key/" + self.id
        self.n.learn(self.arn, "$K1.arn")
        self.n.learn(self.id, "$K1")

    def test_text_names_the_run_keys_and_hides_the_rest(self):
        self.assertEqual(self.n.text("Key '%s' is disabled." % self.arn),
                         "Key '$K1.arn' is disabled.")
        self.assertEqual(self.n.text("key/" + self.id), "key/$K1")
        other = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000000"
        self.assertEqual(self.n.text(other), "arn:aws:kms:REGION:ACCOUNT:key/<uuid>")
        self.assertEqual(self.n.text("mrk-0123456789abcdef0123456789abcdef"), "<mrk>")

    def test_success_keeps_only_what_the_request_fixes(self):
        out = self.n.success({
            "KeyMetadata": {"KeyId": self.id, "Arn": self.arn, "KeySpec": "RSA_2048",
                            "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled",
                            "CreationDate": object(), "Description": "x",
                            "SigningAlgorithms": ["RSASSA_PSS_SHA_256"]},
            "ResponseMetadata": {"RequestId": "r"},
        })
        self.assertEqual(out, {"fields": ["KeyMetadata"], "KeyMetadata": {
            "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled",
            "SigningAlgorithms": ["RSASSA_PSS_SHA_256"]}})

    def test_success_sizes_plaintext_and_hides_other_blobs(self):
        out = self.n.success({"Plaintext": bytes(32), "CiphertextBlob": b"xyz", "KeyId": self.arn})
        self.assertEqual(out, {"fields": ["CiphertextBlob", "KeyId", "Plaintext"],
                               "Plaintext": "<bytes:32>"})

    def test_error_is_type_status_and_normalised_message(self):
        out = self.n.error({"Code": "DisabledException", "Message": self.arn + " is disabled."},
                           400)
        self.assertEqual(out, {"error": "DisabledException", "status": 400,
                               "message": "$K1.arn is disabled."})


def step(case, response, op="Encrypt", request=None):
    return {"case": case, "op": op, "request": request or {"KeyId": "$K1"},
            "response": response}


class Comparing(unittest.TestCase):
    def test_equal_runs_have_no_failures(self):
        a = [step("x", {"error": "NotFoundException", "status": 400, "message": "m"})]
        self.assertEqual(kd.compare(a, a), ([], []))

    def test_a_different_error_type_fails(self):
        a = [step("x", {"error": "NotFoundException", "status": 400, "message": "m"})]
        b = [step("x", {"error": "ValidationException", "status": 400, "message": "m"})]
        failures, _ = kd.compare(a, b)
        self.assertEqual(len(failures), 1)
        self.assertIn("error", failures[0])

    def test_a_different_message_is_a_note_unless_strict(self):
        a = [step("x", {"error": "E", "status": 400, "message": "one"})]
        b = [step("x", {"error": "E", "status": 400, "message": "two"})]
        failures, notes = kd.compare(a, b)
        self.assertEqual((len(failures), len(notes)), (0, 1))
        failures, _ = kd.compare(a, b, strict_messages=True)
        self.assertEqual(len(failures), 1)

    def test_allow_turns_a_listed_difference_into_a_note(self):
        a = [step("x", {"error": "E", "status": 400, "message": ""})]
        b = [step("x", {"error": "F", "status": 400, "message": ""})]
        failures, notes = kd.compare(a, b, [{"case": "x", "path": "error", "why": "known"}])
        self.assertEqual(failures, [])
        self.assertTrue(notes[0].startswith("allowed "))

    def test_missing_extra_and_changed_cases_fail(self):
        a = [step("x", {}), step("y", {})]
        b = [step("x", {}, request={"KeyId": "$K2"}), step("z", {})]
        failures, _ = kd.compare(a, b)
        self.assertEqual(len(failures), 3)
        self.assertTrue(any(re.search(r"^x .*request differs", f) for f in failures))
        self.assertTrue(any(f.startswith("y ") and "not run" in f for f in failures))
        self.assertTrue(any(f.startswith("z") and "not in the recording" in f for f in failures))

    def test_success_against_error_fails_on_every_field(self):
        a = [step("x", {"fields": ["CiphertextBlob"]})]
        b = [step("x", {"error": "E", "status": 400, "message": ""})]
        failures, _ = kd.compare(a, b)
        self.assertGreaterEqual(len(failures), 2)


class Recording(unittest.TestCase):
    """Any checked-in recording was made with today's case list."""

    def test_recordings_match_the_case_list(self):
        import json

        folder = os.path.join(HERE, "recordings")
        if not os.path.isdir(folder):
            self.skipTest("no recordings yet")
        names = [c[0] for c in kd.KEY_SETUP + kd.CASES]
        for f in sorted(os.listdir(folder)):
            if f.startswith("aws-") and f.endswith(".json"):
                with open(os.path.join(folder, f)) as fh:
                    rec = json.load(fh)
                self.assertEqual([s["case"] for s in rec["steps"]], names, f)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
