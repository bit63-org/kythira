#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Offline tests of sqs_differential.py's normaliser and comparison (no
boto3, no network): the ctest sqs_differential_tool."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sqs_differential as d  # noqa: E402


class FakeError(Exception):
    def __init__(self, code, status, message):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class NormaliserTest(unittest.TestCase):
    def test_run_specific_fields_become_placeholders(self):
        n = d.Normaliser()
        got = n.value({"Messages": [{"MessageId": "m-1", "ReceiptHandle": "rh-1", "Body": "b",
                                     "MD5OfBody": "92eb5ffee6ae2fec3ad71c777531578f",
                                     "Attributes": {"SentTimestamp": "1700000000000",
                                                    "ApproximateReceiveCount": "1"}}],
                       "ResponseMetadata": {"RequestId": "r"}})
        m = got["Messages"][0]
        self.assertEqual(m["MessageId"], "<message-id>")
        self.assertEqual(m["ReceiptHandle"], "<receipt>")
        self.assertEqual(m["Attributes"]["SentTimestamp"], "<time>")
        self.assertEqual(m["Attributes"]["ApproximateReceiveCount"], "1")
        self.assertEqual(m["MD5OfBody"], "92eb5ffee6ae2fec3ad71c777531578f")
        self.assertNotIn("ResponseMetadata", got)

    def test_seen_handles_are_replaced_inside_messages(self):
        n = d.Normaliser()
        n.value({"ReceiptHandle": "AQEBabc"})
        err = n.error(FakeError("InvalidParameterValue", 400, "Value AQEBabc for parameter"))
        self.assertEqual(err, {"error": "InvalidParameterValue", "status": 400,
                               "message": "Value <receipt> for parameter"})

    def test_longest_replacement_wins(self):
        n = d.Normaliser()
        n.learn("https://sqs.us-east-1.amazonaws.com", "<endpoint>")
        n.learn("111122223333", "<account>")
        n.learn("kythira-diff-1-abc", "<prefix>")
        self.assertEqual(n.text("https://sqs.us-east-1.amazonaws.com/111122223333/kythira-diff-1-abc-std"),
                         "<endpoint>/<account>/<prefix>-std")

    def test_counts_and_policy_do_not_compare(self):
        n = d.Normaliser()
        got = n.value({"Attributes": {"ApproximateNumberOfMessages": "3", "Policy": "{}",
                                      "VisibilityTimeout": "30"}})
        self.assertEqual(got, {"Attributes": {"ApproximateNumberOfMessages": "<count>",
                                              "VisibilityTimeout": "30"}})


class OrderTest(unittest.TestCase):
    def test_standard_answers_sort_by_body(self):
        self.assertEqual([m["Body"] for m in d.by_body([{"Body": "b"}, {"Body": "a"}])], ["a", "b"])

    def test_fifo_answers_keep_order_per_group(self):
        msgs = [{"Body": "1", "Attributes": {"MessageGroupId": "g1"}},
                {"Body": "2", "Attributes": {"MessageGroupId": "g2"}},
                {"Body": "3", "Attributes": {"MessageGroupId": "g1"}}]
        got = d.by_group(msgs)
        self.assertEqual([m["Body"] for m in got["g1"]], ["1", "3"])
        self.assertEqual([m["Body"] for m in got["g2"]], ["2"])


class RequestTest(unittest.TestCase):
    def test_receipts_are_symbolic_in_the_record_and_real_on_the_wire(self):
        req = {"QueueUrl": "u", "Entries": [{"Id": "d0", "ReceiptHandle": {"$receipt": "rh"}}]}
        self.assertEqual(d.symbolic(req, d.Normaliser())["Entries"][0]["ReceiptHandle"], "<receipt>")
        self.assertEqual(d.resolve(req)["Entries"][0]["ReceiptHandle"], "rh")

    def test_long_text_is_summarised(self):
        got = d.symbolic("x" * 400, d.Normaliser())
        self.assertEqual(got["$text"], 400)


class CompareTest(unittest.TestCase):
    def step(self, op, req, resp):
        return {"op": op, "request": req, "response": resp}

    def test_identical_runs_pass(self):
        a = [self.step("send_message", {"MessageBody": "x"}, {"MD5OfMessageBody": "m"})]
        self.assertEqual(d.compare(a, a), ([], []))

    def test_a_different_answer_fails(self):
        a = [self.step("send_message", {}, {"MD5OfMessageBody": "m"})]
        b = [self.step("send_message", {}, {"MD5OfMessageBody": "n"})]
        failures, _ = d.compare(a, b)
        self.assertEqual(len(failures), 1)
        self.assertIn("MD5OfMessageBody", failures[0])

    def test_batch_entries_compare_in_any_order(self):
        a = [self.step("delete_message_batch", {}, {"Successful": [{"Id": "d1"}, {"Id": "d0"}]})]
        b = [self.step("delete_message_batch", {}, {"Successful": [{"Id": "d0"}, {"Id": "d1"}]})]
        self.assertEqual(d.compare(a, b), ([], []))
        c = [self.step("delete_message_batch", {}, {"Successful": [{"Id": "d0"}, {"Id": "d2"}]})]
        self.assertEqual(len(d.compare(a, c)[0]), 1)

    def test_diverging_requests_stop_the_comparison(self):
        a = [self.step("send_message", {"MessageBody": "x"}, {}), self.step("list_queues", {}, {"a": 1})]
        b = [self.step("send_message", {"MessageBody": "y"}, {}), self.step("list_queues", {}, {"a": 2})]
        failures, _ = d.compare(a, b)
        self.assertEqual(len(failures), 1)
        self.assertIn("stopping", failures[0])

    def test_messages_are_notes_unless_strict(self):
        a = [self.step("get_queue_url", {}, {"error": "QueueDoesNotExist", "status": 400, "message": "a"})]
        b = [self.step("get_queue_url", {}, {"error": "QueueDoesNotExist", "status": 400, "message": "b"})]
        self.assertEqual(len(d.compare(a, b)[1]), 1)
        self.assertEqual(len(d.compare(a, b, strict_messages=True)[0]), 1)

    def test_allow_entries_match_any_index(self):
        a = [self.step("drain_batch", {}, {"messages": [{"Body": "1"}, {"Body": "2"}]})]
        b = [self.step("drain_batch", {}, {"messages": [{"Body": "1"}, {"Body": "3"}]})]
        allow = [{"op": "drain_batch", "path": "messages[*].Body", "why": "test"}]
        failures, notes = d.compare(a, b, allow)
        self.assertEqual(failures, [])
        self.assertTrue(notes[0].startswith("allowed"))

    def test_step_counts_must_match(self):
        a = [self.step("list_queues", {}, {})]
        self.assertIn("step counts differ", d.compare(a, a + a)[0][0])


if __name__ == "__main__":
    unittest.main()
