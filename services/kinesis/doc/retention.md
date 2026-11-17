# Retention, tiering and the disk guard

Task 10 of `.kiro/specs/kinesis-compatible-streams/` (Requirements
11.2-11.4). Records live in the core record segment store
(`include/raft/record_segment_store.hpp`): each shard appends to an active
segment, which rolls at 64 MiB or when a record arrives an hour after the
segment's first. Rolls depend only on records, so every replica of a group
holds byte-identical segments.

## Retention

`IncreaseStreamRetentionPeriod` and `DecreaseStreamRetentionPeriod` take 24
to 8760 hours and change one field of the stream's catalog record. The
refusals carry AWS's messages as we know them (not yet checked against a
recording of AWS): shorter than 24 or longer than 8760 hours,
an increase below the current period (or a decrease above it), and a stream
that is not ACTIVE (`ResourceInUseException`). The same period is accepted
and changes nothing.

Records are dropped by the maintenance pass, never by the clock inside
`apply()`. Every node runs the pass each `KINESIS_MAINTENANCE_INTERVAL_MS`
(a minute by default); for each shard, only the node leading the shard's
group acts:

1. If the active segment's first record is older than the retention period
   (or the tier age), it proposes `seal_shard_command`. Without it an idle
   shard's active segment would never roll, and never be trimmed.
2. It proposes `trim_shard_command` up to the end of the last sealed
   segment whose *last* record is past the period. Every replica drops the
   same segments, and the shard's trim horizon moves there.

So retention is "at least": a record stays readable until every record of
its segment is past the period, up to one segment age (an hour) longer.
AWS documents the same kind of slack. A shorter period takes effect on the
next pass.

## Tiering

With `KINESIS_TIER_AFTER_HOURS` and `KINESIS_TIER_BUCKET` set, the leader
also uploads each sealed segment whose last record is older than the tier
age, then proposes `tier_segment_command`. When it applies, every replica
marks the segment tiered in the shard's state (which the snapshot carries)
and deletes its local copy.

The tier age is in hours. `KINESIS_TIER_AFTER_MS` sets it in milliseconds
instead (at least 1000) and wins when set, so a test or a demo can watch
segments tier within seconds; the container scenario's tiering case uses
five seconds.

- **Object keys are deterministic:**
  `<prefix>kinesis/segments/<hex of the shard's routing key>/<first counter, 20 digits>-<SHA-256 hex>`.
  The state records only *that* a segment is tiered, and any node finds it
  without a lookup.
- **Reads fetch back transparently.** A read that reaches a tiered segment
  asks the node's fetcher, which tries the peers, then the object store. It
  installs the bytes only after checking their size, their SHA-256 against
  the index, and every record's CRC. The copy stays while reads keep wanting
  it, and the pass removes it ten minutes after the last fetch. A segment
  that neither a peer nor the store can supply fails `GetRecords` with
  `InternalFailure`; it is never skipped.
- **Trimming a tiered segment** deletes its object after the trim commits.

### Where segments go

`KINESIS_TIER_PROVIDER` picks the object store, through core's client for
it (`kinesis_tiering.hpp`'s `tier_store` is any `key_object_store` with the
bucket bound). The names are the ones `raft_object_backup --provider`
takes, and each provider reads its credentials where that tool does:

| Provider | Bucket | Endpoint and credentials | In the build when |
|---|---|---|---|
| `s3` (default) | `KINESIS_TIER_BUCKET` | `KINESIS_TIER_S3_REGION` (default `KINESIS_REGION`); `KINESIS_TIER_ENDPOINT` for an S3-compatible store; the AWS SDK's default chain | the AWS SDK's s3 component is found |
| `azure-blob` | the container | `KINESIS_TIER_AZURE_ACCOUNT` (default `KYTHIRA_AZURE_STORAGE_ACCOUNT`), or `KINESIS_TIER_ENDPOINT` naming the whole origin (Azurite); Azure's default credential chain | `CONFIG_AZURE_BLOB_PERSISTENCE=y` and the Azure SDK |
| `gcs` | `KINESIS_TIER_BUCKET` | `GOOGLE_CLOUD_PROJECT`; `KINESIS_TIER_ENDPOINT` for an emulator; Application Default Credentials | `CONFIG_GCP_STORAGE_PERSISTENCE=y` and vcpkg's `gcp` feature |
| `oci-objectstorage` | `KINESIS_TIER_BUCKET` | `KYTHIRA_OCI_*` (region, credentials, optional namespace) | `CONFIG_OCI_OBJECT_PERSISTENCE=y` |
| `oss` | `KINESIS_TIER_BUCKET` | `KYTHIRA_ALIBABA_*` | `CONFIG_ALIBABA_OSS_PERSISTENCE=y` |

`KINESIS_TIER_PREFIX` puts every key under a prefix. `KINESIS_TIER_S3_BUCKET`,
`_S3_PREFIX` and `_S3_ENDPOINT`, the names from when S3 was the only
provider, still work; setting one beside its new name with a different
value is refused. So is a provider this build lacks (the message says what
would enable it), a setting that belongs to another provider, and an
unknown provider name, all at startup, before the node serves.

## When a leader dies mid-pass

Each entry names its segment by first counter (and digest, for a tier), and
does nothing when it has already applied. A new leader therefore simply runs
the pass again. What a dead leader can leave behind:

- **An upload whose tier entry never committed.** Its successor uploads the
  same bytes under the same key.
- **Objects of segments that were trimmed** when it died between the trim
  committing and the deletes. Nothing references them. They stay until an
  operator lists `<prefix>kinesis/segments/` against the catalog, and the
  routing key in each name makes that listing straightforward.

## The disk guard

Below `KINESIS_DISK_FLOOR_BYTES` free on the segment disk (1 GiB by
default; 0 turns it off), appends are refused before they are proposed.
`PutRecord` answers `InternalFailure` and `PutRecords` fails each record
with `InternalFailure`, both with a message that starts
`Kythira disk guard:`. Both the node the client called and the leader that
a forwarded append reaches check their own disks. `apply()` never consults
the guard, because whether an entry applies cannot depend on one replica's
disk. Reads, retention changes, trims and tiering carry on, and they free
the space that lets writes resume. Free space is read with `statvfs` at
most once a second.

## Tests

`kinesis_retention_test` (12 cases) covers:

- the retention calls and their messages;
- the guards on each entry and the snapshot of the tiered list;
- the pass trimming at the period's edge, sealing an idle shard, and acting
  on a shortened period;
- tiering with every local copy gone and reads still whole;
- eviction of fetched copies, and objects deleted on trim;
- a read that fails when a tiered object is missing;
- the disk guard refusing writes while reads go on.
