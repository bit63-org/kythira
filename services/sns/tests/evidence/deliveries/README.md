# Real SNS deliveries

What Amazon SNS itself sends to an HTTPS subscriber, recorded once and
checked in as `deliveries.json`
(`.kiro/specs/sns-compatible-notifications/` task 1). The delivery workers
(task 6) and message signatures (task 7) build against these requests,
not against the documentation's examples.

`record_deliveries.py` runs the whole thing in one account and region and
deletes what it made, also on failure:

- It deploys `capture_lambda.py` behind a Lambda function URL that logs each
  request.
- It creates two topics, one with `SignatureVersion` 1 and one with 2, and
  subscribes the URL three ways: wrapped and raw on the first topic,
  wrapped on the second.
- It confirms the subscriptions, then publishes:
  - a plain message
  - a message with a subject and String, Number and Binary attributes
  - a `MessageStructure` json message
  - a `PublishBatch` of two
- It unsubscribes once and waits a minute for an `UnsubscribeConfirmation`.
  None arrived on either run (November 18, 2026): SNS does not send one
  when the topic owner calls `Unsubscribe`. The file records whether one
  came.
- It reads the requests back from the logs and saves each `SigningCertURL`
  certificate.

Bodies are kept unchanged so their signatures still verify. The capture
host becomes `capture.example`. Headers the function URL adds itself are
dropped (the trace id, the `x-forwarded-*` headers and the TLS details).
Function URLs lower-case header names and do not keep their order, so the
recording has SNS's header values but not its spelling or order.

It costs well under $0.01 a run. Like every real-cloud run in this
repository, it needs Clark's go before it runs.

```
python3 -m venv /tmp/rec && /tmp/rec/bin/pip install -r ../requirements.txt
AWS_PROFILE=<profile> /tmp/rec/bin/python record_deliveries.py --region us-east-1
python3 check_deliveries.py deliveries.json
```

`check_deliveries.py` checks two things. Every delivery's `x-amz-sns-*`
headers must agree with its body. Every signed message must verify against
its saved certificate by the string SNS documents: SHA1withRSA for version
1 and SHA256withRSA for version 2. The recording from November 18, 2026 holds 14 deliveries (3
`SubscriptionConfirmation`, 11 `Notification`, 2 of them raw) and all 9
signed messages verify, version 1 and 2. `sns_real_deliveries` runs the
check in ctest. Its `--self-test` signs synthetic
messages with a throwaway key, so the checker is tested even without a
recording.
