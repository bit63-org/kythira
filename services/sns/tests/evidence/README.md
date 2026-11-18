# SNS wire evidence

This directory holds what real SNS clients put on the wire. Each client was
recorded once against a stub and the recordings are checked in
(`.kiro/specs/sns-compatible-notifications/` task 1). The gateway's query
codec (task 3), the API (task 4) and the client suites (task 11) build
against these files, not against what the documentation implies.

## How it is recorded

`recorder.py` is a small SNS stub on 127.0.0.1. It keeps topics,
subscriptions and tags in memory, which is enough for each client to finish
the scenario below. It records every request: the request line, the HTTP
version, every header, and the form body as an ordered list of
`[name, value]` pairs, exactly as the client flattened it. Values that
change on every call (signature, date, invocation id, port, kernel) are
replaced with a placeholder of the same shape. botocore's feature-id list in
the user agent is sorted, because botocore emits it in set order. The stub
answers in SNS's XML. Anything it does not script gets `InvalidAction`.

`run_client.sh` starts a recorder and runs one client against it with dummy
keys. The signature is real SigV4, but nothing can reach AWS. It writes
`data/<client>.json`. `record_all.sh` re-records every client and then runs
the check. A rerun with the same client versions reproduces the files byte
for byte.

The ctest `sns_wire_evidence` (`check_evidence.py`) checks four things:
- every action is in the pinned model;
- every request was answered 200, so the scenario ran to the end;
- `Action` and `Version=2010-03-31` are on every request;
- the volatile headers are normalised.

It then decodes each request the way the query codec must, with map entries
keyed by name and lists in member order. Every client must decode to the
same sequence of requests.

| Client | Version | File |
|---|---|---|
| AWS CLI v2 | 2.31.0 | `data/awscli-v2.json` |
| boto3 | 1.43.126 (botocore 1.43.126, the model pin) | `data/boto3.json` |
| aws-sdk-java-v2 | 2.57.11, sync client, URL connection HTTP | `data/java-sdk-v2.json` |
| AWS SDK for JavaScript v3 | `@aws-sdk/client-sns` 3.1166.0 (its user agent says 3.1165.0) | `data/js-sdk-v3.json` |
| AWS SDK for Go v2 | `service/sns` 1.47.10, core 1.48.0 | `data/go-sdk-v2.json` |

### The scenario

Every client runs the same 21 requests, so the files can be compared request
by request:

1. `CreateTopic` `evidence`, with a `DisplayName` attribute and a tag.
2. `CreateTopic` `evidence.fifo`, with `FifoTopic` and
   `ContentBasedDeduplication`.
3. `ListTopics`, then `GetTopicAttributes`, then `SetTopicAttributes`.
4. `Subscribe` an SQS queue with `RawMessageDelivery`, a `FilterPolicy` and
   `ReturnSubscriptionArn`.
5. `Subscribe` an HTTP endpoint. The answer is `pending confirmation`, and
   every SDK accepts it.
6. `ConfirmSubscription` with a token and `AuthenticateOnUnsubscribe`.
7. `ListSubscriptionsByTopic`, then `SetSubscriptionAttributes`
   (`FilterPolicyScope`), then `GetSubscriptionAttributes`.
8. `Publish` with a subject and four message attributes: `String`,
   `Number`, `Binary` and `String.Array`.
9. `Publish` with `MessageStructure=json`.
10. `Publish` to the FIFO topic with a group id. The client reads back the
    `SequenceNumber`.
11. `PublishBatch` of two FIFO entries: one with an explicit dedup id, one
    with a message attribute.
12. `TagResource`, then `ListTagsForResource`, then `UntagResource`.
13. `Unsubscribe`, then `DeleteTopic` for both topics.

## What the gateway must accept

| | AWS CLI v2 | boto3 | Java SDK v2 | JS SDK v3 | Go SDK v2 |
|---|---|---|---|---|---|
| Request | `POST /`, HTTP/1.1 | same | same, keep-alive | same, keep-alive | same |
| `Content-Type` | `application/x-www-form-urlencoded; charset=utf-8` | same | same | **no charset** | **no charset** |
| `x-amz-content-sha256` | absent | absent | present, signed | present, signed | absent |
| Signed headers | content-type, host, x-amz-date | same | adds amz-sdk-invocation-id, amz-sdk-request, content-length, x-amz-content-sha256 | the Java set plus **x-amz-user-agent** | amz-sdk-invocation-id, amz-sdk-request, content-length, content-type, host, x-amz-date |
| `Accept-Encoding` | `identity` | `identity` | absent | absent | **`gzip`** |
| Parameter order | `Action`, `Version`, then CLI argument order (`Endpoint` after `ReturnSubscriptionArn`) | `Action`, `Version`, then model order | same as boto3 | `Action`, `Version`, then the order the input was written in | **sorted by name**, so `Version` is last |
| Map entry numbering | insertion order | insertion order | the map's iteration order | insertion order | **sorted by key** |

What every client did the same way:
- Attribute maps are sent as `Attributes.entry.N.key` and `.value`.
- Message attributes are sent as `MessageAttributes.entry.N.Name`,
  `.Value.DataType`, and `.Value.StringValue` or `.Value.BinaryValue`. Binary
  values are base64 (`AAH+/w==`).
- Lists are sent as `X.member.N`, and batch entries as
  `PublishBatchRequestEntries.member.N.<field>`, nested maps included.
- Booleans are sent as `true`.
- Empty requests (`ListTopics`) carry only `Action` and `Version`.
- No client sent `Expect: 100-continue`.
- No client used HTTP/2.

Consequences for later tasks:

- **Decode by name, never by index or position.** The Go SDK sorts map keys
  before numbering them, so `entry.1` is a different attribute than from
  other clients. Parameters can arrive in any order: `Action` is not always
  first, and `Version` can be last. Task 3's codec must collect each
  `entry.N` group and key it by its `key` or `Name`, and order lists by `N`.
  The codec must reject gaps and duplicates, as `check_evidence.py`'s
  reference decoder does.
- **The charset parameter is optional** on the content type. Both spellings
  must be accepted.
- **Signed `x-amz-user-agent`.** The JS SDK signs it, so a proxy or the
  gateway must not rewrite it before SigV4 verification.
- **`Accept-Encoding: gzip`** from Go: the gateway can ignore it (Go copes
  with an identity body), or compress the XML. Either is valid.
- **`x-amz-content-sha256` is optional.** When it is present it is the hex
  digest of the form body, and the verifier must check it. When it is absent
  the verifier hashes the body itself.
- **`pending confirmation` is a literal string** in `SubscriptionArn`.
  Clients pass it through without parsing, so the gateway must send it
  verbatim (Requirement 4.2).

## Not recorded yet, and why

| What | When | Why not now |
|---|---|---|
| SNS's own HTTP/HTTPS deliveries (`SubscriptionConfirmation`, `Notification` and `UnsubscribeConfirmation` POSTs with their `x-amz-sns-*` headers and signatures) | the rest of task 1, or task 12's real-cloud bundle | Only real SNS can produce them, and it needs a public HTTPS endpoint. That is real-cloud spend, which needs Clark's go. |
| Error responses from real SNS | task 12 (differential fixtures) | This directory records requests. Real error bodies come from recordings against AWS. |
