# SQS wire evidence

What real SQS clients put on the wire, recorded once against a stub and
checked in (`.kiro/specs/sqs-compatible-queues/` task 1). The gateway and
both protocol codecs (task 3), the handlers (task 4) and the client suites
(task 12) build against these files, not against what the documentation
implies.

## How it is recorded

`recorder.py` is a small SQS stub on 127.0.0.1. It keeps queues, messages
and visibility in memory, which is enough for each client to finish one
scripted scenario. It records every request: the request line, the HTTP
version, every header and the body (for the query protocol, both the form
parameters as sent and the same request decoded into the JSON shape).
Values that change on every call (signature, date, invocation id, port) are
replaced with a placeholder of the same shape, and maps are written with
sorted keys, so re-recording with the same client versions gives the same
files. It answers in the protocol the request used, with MD5 digests of
bodies, message attributes and system attributes computed as SQS computes
them, and gives `UnsupportedOperation` for anything it does not script.

`run_client.sh` starts a recorder, runs one client against it with dummy
keys (the signature is real SigV4, but nothing can reach AWS), and writes
`data/<client>.json`. `record_all.sh` re-records every client; two runs in a
row gave identical files. The ctest `sqs_wire_evidence` checks the files:
every operation is in the pinned model, every scenario finished (only the
errors it provokes on purpose), the protocol is the one this table claims,
and the volatile values are normalised.

| Client | Version | Scenario | File |
|---|---|---|---|
| AWS CLI v2 | 2.31.0 | create, get URL and attributes, list, send with attributes, send batch, receive, change visibility, delete, purge, delete queue | `data/awscli-v2.json` |
| boto3 | 1.43.100 (botocore 1.43.100, the model pin) | queue API and tags; send with String, Number and Binary attributes and `AWSTraceHeader`; batches; receive with all attributes; visibility and its batch; delete and its batch; purge; a FIFO queue with group and deduplication ids; `GetQueueUrl` of the deleted queue | `data/boto3.json` |
| boto3, query protocol | 1.28.40 (botocore 1.31.40) | the same script | `data/boto3-query.json` |
| aws-sdk-java-v2 | 2.57.11, sync client, URL connection HTTP | the boto3 scenario | `data/java-sdk-v2.json` |
| Amazon SQS Java Messaging Library (JMS) | 2.1.5 on SDK 2.57.11 | create the queue if missing, send a text message with properties, consume with client acknowledgement | `data/jms.json` |
| Kombu (Celery's transport) | 5.5.4 on boto3 1.43.100 and pycurl 7.49.0 | declare a queue, publish a task message, consume and ack it, delete the queue | `data/kombu.json` |

## What the gateway must accept

| | AWS CLI v2, boto3, Kombu | Java SDK v2, JMS | boto3 1.28 (query) |
|---|---|---|---|
| Body | AWS JSON 1.0 (`X-Amz-Target: AmazonSQS.<Action>`) | AWS JSON 1.0 | form-encoded, `Action` and `Version=2012-11-05`, queue named by `QueueUrl` in the form |
| `x-amzn-query-mode: true` | sent and signed | sent and signed | absent |
| Signed headers | content-type, host, x-amz-date, x-amz-target, x-amzn-query-mode | adds amz-sdk-invocation-id, amz-sdk-request, content-length, x-amz-content-sha256 | content-type, host, x-amz-date |
| `x-amz-content-sha256` | absent | present (hex) | absent |
| HTTP | 1.1 | 1.1, keep-alive | 1.1 |
| ReceiveMessage asks for system attributes with | `AttributeNames` (deprecated name) | `MessageSystemAttributeNames` (SDK); JMS still uses `AttributeNames` | `AttributeName.N` |

Consequences for later tasks:

- **Every current client asks for query-compatible errors.** All the JSON
  clients send and sign `x-amzn-query-mode: true`. The gateway (task 3)
  must then answer errors with the model's shape name in `__type`
  (`com.amazonaws.sqs#QueueDoesNotExist`) and the query error code in
  `x-amzn-query-error` (`AWS.SimpleQueueService.NonExistentQueue;Sender`);
  the Java SDK mapped exactly that back to `QueueDoesNotExistException`.
  The query codes are not in the pinned model (botocore strips them), so
  task 3 keeps its own table, checked against task 13's recorded SQS
  responses.
- **Both attribute-name fields.** `ReceiveMessage` must accept
  `AttributeNames` and `MessageSystemAttributeNames` and take their union;
  the CLI, boto3, Kombu and JMS still send the deprecated one.
- **MD5 digests are checked by the Java SDK.** aws-sdk-java-v2 verifies
  `MD5OfMessageBody`, `MD5OfMessageAttributes` and
  `MD5OfMessageSystemAttributes` on send and on receive and failed the
  scenario until they were right. boto3 checks nothing. The stub's
  algorithm (`md5_of_attributes` in `recorder.py`) also matches moto's for
  the boto3 scenario's attributes, so task 4 can take it as the reference.
- **JMS long-polls for 20 s with one message at a time** and prefetches, so
  it keeps a second `ReceiveMessage` parked; it acknowledges with
  `DeleteMessageBatch` and adds a `JMS_SQSMessageType` attribute. Long
  polling (task 5) is on the first JMS path, and a parked receive must not
  hold the connection's other requests back.
- **Kombu** creates its queue with `VisibilityTimeout=1800`, looks queues up
  with `ListQueues` prefixes, polls `GetQueueAttributes`
  (`ApproximateNumberOfMessages`) and receives ten at a time with a short
  wait and no attributes.
- **The query protocol is still worth serving**: SDKs from before late
  2023 (aws-sdk-java v1 up to 1.12.575 among them) speak it, and Requirement
  3.1 asks for it.

## Not recorded yet, and why

| Client | When | Why not now |
|---|---|---|
| Spring Cloud AWS | task 12 (done) | Its template and listener container run end to end in `../clients/` instead. |
| SQS Extended Client | task 12 (done) | It needs S3 for its payloads; `../clients/` runs it with moto as S3. |
| aws-sdk-java v1 (query) | task 12 (done) | The boto3 query recording covers the protocol; `../clients/` runs v1 1.12.575, the last query-era release (1.12.585 on speak AWS JSON 1.0). |
