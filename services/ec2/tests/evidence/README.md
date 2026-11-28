# EC2 wire evidence

This directory holds what real EC2 clients put on the wire. Each client was
recorded once against a stub and the recordings are checked in
(`.kiro/specs/ec2-compatible-api/` task 1). The EC2 query codec (task 2),
the gateway (task 3) and the client suites (task 18) build against these
files, not against what the documentation implies.

## How it is recorded

`recorder.py` is a small EC2 stub on 127.0.0.1. It keeps VPCs, subnets,
volumes, instances and tags in memory, which is enough for each client to
finish the scenario below, and hands out IDs in EC2's 17-hex-digit shape
from one counter, so every client sees the same IDs. It records every
request: the request line, the HTTP version, every header, and the form
body as an ordered list of `[name, value]` pairs, exactly as the client
flattened it. Values that change on every call (signature, date,
invocation id, port, kernel, and a `ClientToken` the client made up itself)
are replaced with a placeholder of the same shape. botocore's feature-id
list in the user agent is sorted, because botocore emits it in set order.
The stub answers in EC2's XML (`<ActionResponse xmlns=...><requestId>`,
lists of `<item>`, errors as `<Response><Errors><Error>`).

`run_client.sh` starts a recorder and runs one client against it with dummy
keys. The signature is real SigV4, but nothing can reach AWS. It writes
`data/<client>.json`. `record_all.sh` re-records every client and then runs
the check. A rerun with the same client versions reproduces the files byte
for byte.

The ctest `ec2_wire_evidence` (`check_evidence.py`) checks that:
- every action is in the pinned model;
- every request was answered 200, except the scenario's two deliberate
  refusals, so the scenario ran to the end;
- `Action` and `Version=2016-11-15` are on every request;
- the volatile headers are normalised.

It then decodes each request the way the EC2 codec must: a name segment
that is a positive number is a list index, so `Filter.1.Value.2` is the
second value of the first filter, and parameter order does not matter.
Every client must decode to the same sequence of requests.

| Client | Version | File |
|---|---|---|
| AWS CLI v2 | 2.31.0 (installed from its source tag) | `data/awscli-v2.json` |
| boto3 | 1.43.126 (botocore 1.43.126, the model pin) | `data/boto3.json` |
| aws-sdk-java-v2 | 2.57.11, sync client, URL connection HTTP | `data/java-sdk-v2.json` |
| AWS SDK for JavaScript v3 | `@aws-sdk/client-ec2` 3.1166.0 (its user agent says 3.1165.0) | `data/js-sdk-v3.json` |
| AWS SDK for Go v2 | `service/ec2` 1.350.2, core 1.48.2 | `data/go-sdk-v2.json` |

Terraform's AWS provider is not recorded yet. It does not run a fixed
script: each resource reads back attributes, waits on states and refreshes,
so its recording needs a stub that answers far more calls than this
scenario (`DescribeVpcAttribute`, `DescribeInstanceAttribute`, the default
route table, network ACL and security group of a VPC). It joins with task
18's Terraform suite.

### The scenario

Every client runs the same 25 requests, so the files can be compared request
by request:

1. `DescribeRegions` for one region, then `DescribeAvailabilityZones` with a
   `state` filter.
2. `CreateVpc` with a `TagSpecification` of two tags, `CreateSubnet`, and
   `DescribeVpcs` by ID with a `tag:Name` filter.
3. `CreateVolume` with `Encrypted`, a `ClientToken` and a tag, and a second
   `CreateVolume` with `Iops` and `Throughput` and no token.
4. `DescribeVolumes` with a filter and `MaxResults`, whose answer carries a
   `NextToken`, then the second page with it.
5. `RunInstances` with `MinCount` 1 and `MaxCount` 2, a `ClientToken`,
   `UserData`, an `Ebs` and an `ephemeral0` block-device mapping, and tag
   specifications for the instance and its volumes.
6. The same `RunInstances` with `DryRun=true`, answered `DryRunOperation`
   (HTTP 412).
7. `DescribeInstances` by two IDs with a two-value state filter.
8. `CreateTags` on two resources (one tag without a value), `DescribeTags`
   with two filters, `DeleteTags`.
9. `AttachVolume`, `DetachVolume`.
10. `StopInstances`, `StartInstances`, `TerminateInstances`.
11. `CreateSecurityGroup`, answered `UnsupportedOperation` (HTTP 400), as
    Requirement 14.1 has Kythira answer it.
12. `DeleteVolume` twice, `DeleteSubnet`, `DeleteVpc`.

## What the gateway must accept

| | AWS CLI v2 | boto3 | Java SDK v2 | JS SDK v3 | Go SDK v2 |
|---|---|---|---|---|---|
| Request | `POST /`, HTTP/1.1 | same | same, keep-alive | same, keep-alive | same |
| `Content-Type` | `application/x-www-form-urlencoded; charset=utf-8` | same | same | **no charset** | **no charset** |
| `x-amz-content-sha256` | absent | absent | present, signed | present, signed | absent |
| Signed headers | content-type, host, x-amz-date | same | adds amz-sdk-invocation-id, amz-sdk-request, content-length, x-amz-content-sha256 | the Java set plus **x-amz-user-agent** | amz-sdk-invocation-id, amz-sdk-request, content-length, content-type, host, x-amz-date |
| `Accept-Encoding` | `identity` | `identity` | absent | absent | **`gzip`** |
| Parameter order | `Action`, `Version`, then its own order | `Action`, `Version`, then model order | `Action`, `Version`, then its own order | `Action`, `Version`, then its own order | **sorted by name**, so `Version` comes late |

Findings the codec and front end depend on:

- **Every client sends a `ClientToken` on every operation that has one**,
  a random UUID when the caller gives none (the model's `idempotencyToken`
  trait). So the idempotency index (Requirement 4.3) sees a token on every
  `CreateVolume` and `RunInstances`, not only on the ones a user meant to
  retry, and must size and expire for that.
- Lists flatten as `Name.N` with no `.member`, and nested lists as
  `Filter.N.Value.M` and `TagSpecification.N.Tag.M.Key`; numbering starts at
  1 with no gaps in every recording.
- A tag without a value is sent as `Tag.N.Key` alone (no empty `Value`).
- Booleans are `true` and `false`; `UserData` arrives base64-encoded from
  every client (boto3 and the CLI encode it themselves, the other SDKs send
  what the caller gives).
- No client retried `DryRunOperation` (412) or `UnsupportedOperation` (400):
  each of the 25 requests was sent once.
