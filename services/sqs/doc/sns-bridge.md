# The SNS bridge

`.kiro/specs/sqs-compatible-queues/` Requirements 10.1 and 14.1, task 9.
The code is `../include/kythira/sqs/sqs_sns_bridge.hpp`; the node wiring is
`../cmd/sqs_node/sns_bridge_setup.hpp`.

Amazon SNS cannot deliver to a queue outside AWS, but it can deliver to an
HTTPS endpoint. The bridge is that endpoint, so a real SNS topic can feed a
Kythira queue. Kythira's own SNS delivers to Kythira SQS directly and does
not use the bridge (Requirement 10.2).

## Turning it on

1. Start the nodes with `SQS_SNS_BRIDGE=on`. The listener must be HTTPS
   with a certificate SNS trusts (a public CA), on an address SNS can
   reach.
2. Let the queue take deliveries, with tags (setting them needs
   `sqs:TagQueue` on the queue):
   - `kythira:sns-bridge-topics`: the topic ARNs it takes, comma-separated,
     or `*` for any topic of the queue's own account. This stands in for
     the queue policy that lets `sns.amazonaws.com` send on SQS.
   - `kythira:sns-bridge-raw`: `true` for raw message delivery.
3. Subscribe `https://<SQS_ENDPOINT host>/sns-bridge/<account>/<queue>` to
   the topic as an `https` subscription. Leave SNS's own raw delivery off,
   so every request is signed; the queue's tag chooses raw or wrapped.

The bridge confirms the subscription itself by fetching its
`SubscribeURL`.

```
aws sqs tag-queue --queue-url "$KYTHIRA_QUEUE_URL" \
  --tags kythira:sns-bridge-topics=arn:aws:sns:us-east-1:111122223333:orders
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:111122223333:orders \
  --protocol https \
  --notification-endpoint https://sqs.example.net/sns-bridge/111122223333/orders
```

## What it checks

- Every request's SNS signature, version 1 (SHA1withRSA) or 2
  (SHA256withRSA), against the signing certificate.
- Certificates and subscribe URLs come only from `SQS_SNS_CERT_HOSTS`
  (default `sns.<region>.amazonaws.com`), over HTTPS, chained to
  `SQS_SNS_CA`. Certificates are cached.
- The topic is one the queue's tag allows, and the queue exists in the
  account the path names.

## What lands in the queue

The same as SNS's own SQS delivery: the JSON notification envelope as the
body, or with `kythira:sns-bridge-raw=true` the message itself, with its
SNS message attributes as SQS message attributes. The send goes through
the normal path, so encryption, delays and redrive apply.

## Answers and retries

| Answer | When | SNS then |
|---|---|---|
| 200 | delivered, or a subscription confirmed | stops |
| 4xx | never deliverable: unknown queue, topic not allowed, bad signature, bridge off for the path | stops after its retry policy |
| 5xx | may work later: certificate or subscribe URL not fetched, send not committed | retries |

## Limits

- Standard queues only: SNS delivers to HTTPS endpoints only from standard
  topics.
- A replayed request is taken again, because a signature does not expire.
  A standard queue already delivers at least once, so consumers handle a
  duplicate.
- The real-SNS run is part of task 13's real-cloud bundle, which needs
  Clark's go per run. The unit tests sign requests with a certificate they
  make themselves.
