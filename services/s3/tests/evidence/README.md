# S3 wire evidence

What real S3 clients put on the wire, recorded once against a stub and
checked in (`.kiro/specs/s3-compatible-storage/` task 1). The REST-XML codec
(task 3), the gateway's SigV4 and streaming checks (task 6), the checksums
(task 8) and the conformance jobs (task 21) build against these files, not
against what the documentation implies.

## How it is recorded

`recorder.py` is a small S3 stub on 127.0.0.1, served over HTTPS under a
throwaway CA, because several clients sign and frame bodies differently
over plain HTTP. It keeps buckets, objects and multipart uploads in memory,
which is enough for each client to finish one scripted scenario, and
records every request: the operation (routed the way the gateway will
route it), the target, the addressing style, the HTTP version, every
header, whether the client sent `Expect: 100-continue`, and the body.
Object bytes are kept only as their length and SHA-256 after the
`aws-chunked` framing is removed; the framing itself is described (chunk
sizes, whether chunks and trailer are signed, trailer names). Values that
change on every call (signature, date, invocation id, port, kernel, the
SDKs' unordered feature list, rclone's mtime) are replaced with a
placeholder of the same shape. Anything it does not script gets
`NotImplemented` (501).

`run_client.sh` starts a recorder, runs one client against
`https://s3.kythira.test:<port>` with dummy keys (the signature is real
SigV4, but nothing can reach AWS), and writes `data/<client>.json`.
`record_all.sh` builds the Java, Go and JS clients and re-records every
client. Virtual-hosted requests need two names to resolve locally:

```
127.0.0.1 s3.kythira.test evidence.s3.kythira.test
```

in `/etc/hosts`. Mountpoint's CRT trusts only the system store, so its run
installs the CA there for the duration; `record_all.sh` therefore runs as
root, or with `SKIP_MOUNTPOINT=1`.

The ctest `s3_wire_evidence` (`check_evidence.py`) checks the files: every
operation is in the pinned model, every scenario finished (2xx, or a 404
`HeadObject` probe), nothing volatile was left unnormalised, and each
client's addressing and upload framing are the ones the table below
claims. Re-recording a client at the same version gives a byte-identical
file, except Mountpoint's: the number and order of its FUSE lookup probes
(`HeadObject`, `ListObjectsV2` with `max-keys=1`) vary from run to run.

| Client | Version | Scenario | File |
|---|---|---|---|
| AWS CLI v2 | 2.31.0 | `s3 mb`, `s3 cp` up (small, 17 MiB multipart) and down (ranged parts), `s3 ls`, server-side `s3 cp`, `s3 presign`, `s3 rm --recursive`, `s3 rb`; s3api head-bucket, head-object, ranged get-object, create and abort a multipart upload | `data/aws-cli-v2.json` |
| boto3 | 1.43.126 (botocore 1.43.126, the model pin) | bucket create, head, location; PutObject (default checksum, then SHA-256), HEAD, ranged GET; 17 MiB through the transfer manager; ListObjectsV2 and ListObjects; copy; presigned GET twice (boto3's default, then SigV4); create, list and abort an upload; DeleteObjects, DeleteObject, DeleteBucket, ListBuckets | `data/boto3.json` |
| aws-sdk-java-v2 | 2.59.3, sync `S3Client`, Apache HTTP client | the same, with an explicit two-part multipart upload and `S3Presigner` | `data/java-sdk-v2.json` |
| aws-sdk-go-v2 | `service/s3` v1.115.0, `feature/s3/manager` v1.23.26 | the same, multipart through the upload manager (12 MiB at 5 MiB parts) | `data/go-sdk-v2.json` |
| aws-sdk-js-v3 | 3.1171.0 (`client-s3`, `lib-storage`, `s3-request-presigner`), Node 22 | the same, multipart through `lib-storage`'s `Upload` | `data/js-sdk-v3.json` |
| rclone | 1.71.2, provider AWS, 5 MiB upload cutoff and chunk size | `mkdir`, `copyto` (small, 12 MiB multipart), `lsl`, `cat`, server-side `copyto`, `deletefile`, `purge` | `data/rclone.json` |
| Mountpoint for Amazon S3 | 1.25.0 (CRT S3 client 1.5.2) | mount, write a small file and a 12 MiB file, `ls`, read back, `rm`, unmount | `data/mountpoint.json` |

## What the gateway must accept

| | CLI v2 | boto3 | Java v2 | Go v2 | JS v3 | rclone | Mountpoint |
|---|---|---|---|---|---|---|---|
| Addressing (custom endpoint, defaults) | path | path | virtual-hosted | virtual-hosted | virtual-hosted | virtual-hosted | virtual-hosted |
| Object body `x-amz-content-sha256` | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | same | same | same | **hex SHA-256 of the body** | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | same |
| Checksum on uploads | CRC64NVME trailer | CRC32 trailer (SHA-256 when asked) | CRC32 trailer | CRC32 trailer | CRC32 **header** | CRC32 trailer, plus `Content-MD5` on PutObject and UploadPart, `x-amz-meta-md5chksum` on CreateMultipartUpload | CRC32C trailer |
| Framing under `aws-chunked` | HTTP `Transfer-Encoding: chunked` | same | `Content-Length` | `Content-Length` | none | `Content-Length` | `Content-Length` |
| `aws-chunked` chunk size | 1 MiB | 1 MiB | 128 KiB | whole part | — | whole part | whole part |
| `Expect: 100-continue` | PutObject, UploadPart | PutObject, UploadPart | UploadPart | UploadPart | UploadPart | UploadPart | never |
| Other bodies (`x-amz-content-sha256`) | hex | hex | **`UNSIGNED-PAYLOAD`** on every call | hex | hex | hex | `UNSIGNED-PAYLOAD` |
| Presigned GET | SigV4 query | **SigV2 query by default** (`AWSAccessKeyId`, `Signature`, `Expires`); SigV4 when configured | SigV4 query | SigV4 query with `X-Amz-Checksum-Mode=ENABLED` | SigV4 query with `X-Amz-Content-Sha256=UNSIGNED-PAYLOAD` | — | — |

Consequences for later tasks:

- **Every upload but the JS SDK's is `aws-chunked` with an unsigned
  trailer.** No client sent signed chunks (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`)
  over HTTPS; all but the JS SDK send `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
  with a checksum trailer and `X-Amz-Decoded-Content-Length`. Task 6's
  streaming decoder and task 8's trailing checksums are on the path of the
  very first `aws s3 cp`, not an edge case. The signed-chunk forms still
  need support (Requirement 4.2); clients use them over plain HTTP.
- **Five checksum algorithms on the default path.** The CLI defaults to
  CRC64NVME, the SDKs and rclone to CRC32, Mountpoint to CRC32C, and boto3
  sends SHA-256 when asked; CreateMultipartUpload names the algorithm in
  `x-amz-checksum-algorithm`. CLI, boto3, Go and rclone then complete the
  upload without per-part checksums in the XML; JS and Mountpoint include
  them. Task 8 must accept both and compute full-object checksums itself.
- **Two transfer framings at once.** The AWS CLI and boto3 send
  `aws-chunked` inside HTTP/1.1 chunked transfer coding, with no
  `Content-Length`; the rest send `Content-Length` of the encoded body.
  The gateway must undo both layers while streaming.
- **Addressing is split.** The Python clients default to path style
  against a custom endpoint; everything else defaults to virtual-hosted,
  so `<bucket>.<endpoint>` DNS and a wildcard certificate are required
  for a working deployment, not optional (Requirement 4.1). Task 23's
  docs must say so.
- **boto3's default presigned URLs are SigV2.** Against a custom
  endpoint in `us-east-1`, `generate_presigned_url` signs with SigV2
  query parameters unless `signature_version="s3v4"` is set. Requirement
  4.2 refuses SigV2, so task 6 must answer it with S3's error and task 23's
  docs must tell boto3 users to set `s3v4`.
- **Query keys that do not route.** The Go and JS SDKs and rclone add
  `x-id=<Operation>` to most requests and spell flag sub-resources with an
  empty value (`?uploads=`, `?delete=`, `?versioning=`). The router must
  ignore `x-id` and treat `?uploads` and `?uploads=` alike.
- **Odd ETags.** Mountpoint sends part ETags in CompleteMultipartUpload
  without quotes; Go and rclone escape the quotes as `&#34;`, Java and JS
  as `&quot;`. Part matching must compare unquoted values.
- **Probes and extras.** rclone sends CreateBucket before every command
  (and treats success as fine), asks GetBucketVersioning before `purge`,
  and probes with HeadObject expecting 404. Mountpoint probes with
  `max-keys=0` and `max-keys=1` listings and sends
  `x-amz-optional-object-attributes: RestoreStatus`. Java sends
  `x-amz-te: append-md5` on GetObject. The CLI, boto3, Go, JS and rclone
  send `x-amz-checksum-mode: ENABLED` on reads, so GetObject must return
  stored checksums when asked (task 8).
- **ListObjectsV2 with `encoding-type=url`.** The CLI, boto3 and rclone
  ask for URL-encoded keys and decode them; the response must encode keys,
  prefixes and delimiters exactly when asked.

## Not recorded yet, and why

| Client | When | Why not now |
|---|---|---|
| Browser POST uploads | task 6 | Need an HTML form or a POST policy client; boto3's `generate_presigned_post` output is tested against the gateway there. |
| Plain-HTTP runs (signed `aws-chunked`) | task 6 | Clients use signed chunks only without TLS; the gateway's tests take vectors from `tests/sigv4_chunked/` (botocore-signed). |
| Spark, Trino, Terraform's S3 backend, s3fs | task 21 | They run end to end against the gateway in the conformance job; they use the Java and Go SDKs or libcurl recorded here. |
| Kythira's own `aws_s3_client.hpp` | task 21 | Runs against the gateway in CI (Requirement 17.3). |
