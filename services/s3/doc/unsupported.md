# S3 operations not implemented

`.kiro/specs/s3-compatible-storage/` Requirement 2.1: every operation in the
pinned model (`../model/s3-2006-03-01.json`, botocore 1.43.126) is either
implemented, and then listed in `../implemented-operations.txt`, or listed
here with its reason and the exact error it returns.
`tools/check_coverage.py` (the ctest `s3_model_coverage`) fails when an
operation is in neither list, so a model upgrade that adds one fails until it
is placed (Requirement 2.2).

An operation listed here is answered as S3 answers a feature it does not
implement: the XML error `NotImplemented` ("A header you provided implies
functionality that is not implemented") with HTTP status 501, which every
SDK surfaces as a non-retryable service error (`s3_service.hpp`).

The model has 116 operations. 75 are implemented; the other 41 (`none`)
are out of the spec's scope, or were added to S3 after the spec was
written and wait on the owner's decision.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `CreateBucketMetadataConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `CreateBucketMetadataTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `CreateSession` | none | Out of scope: S3 Express One Zone directory buckets. | `NotImplemented`, HTTP 501 |
| `DeleteBucketAnalyticsConfiguration` | none | Out of scope: S3 Analytics (storage class analysis). | `NotImplemented`, HTTP 501 |
| `DeleteBucketIntelligentTieringConfiguration` | none | Not in the spec: the Intelligent-Tiering archive tiers. Storage classes map to Kythira tiers through lifecycle (task 13). | `NotImplemented`, HTTP 501 |
| `DeleteBucketInventoryConfiguration` | none | Out of scope: S3 Inventory. | `NotImplemented`, HTTP 501 |
| `DeleteBucketMetadataConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `DeleteBucketMetadataTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `DeleteBucketMetricsConfiguration` | none | Not in the spec: CloudWatch request-metrics filters. Kythira exports its own metrics instead. | `NotImplemented`, HTTP 501 |
| `DeleteObjectAnnotation` | none | Not in the spec: object annotations, added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `GetBucketAbac` | none | Not in the spec: bucket ABAC (tag-based access to general purpose buckets), added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `GetBucketAccelerateConfiguration` | none | Out of scope: Transfer Acceleration. | `NotImplemented`, HTTP 501 |
| `GetBucketAnalyticsConfiguration` | none | Out of scope: S3 Analytics (storage class analysis). | `NotImplemented`, HTTP 501 |
| `GetBucketIntelligentTieringConfiguration` | none | Not in the spec: the Intelligent-Tiering archive tiers. Storage classes map to Kythira tiers through lifecycle (task 13). | `NotImplemented`, HTTP 501 |
| `GetBucketInventoryConfiguration` | none | Out of scope: S3 Inventory. | `NotImplemented`, HTTP 501 |
| `GetBucketMetadataConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `GetBucketMetadataTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `GetBucketMetricsConfiguration` | none | Not in the spec: CloudWatch request-metrics filters. Kythira exports its own metrics instead. | `NotImplemented`, HTTP 501 |
| `GetObjectAnnotation` | none | Not in the spec: object annotations, added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `GetObjectTorrent` | none | Not in the spec: BitTorrent, which S3 no longer offers to new accounts. | `NotImplemented`, HTTP 501 |
| `ListBucketAnalyticsConfigurations` | none | Out of scope: S3 Analytics (storage class analysis). | `NotImplemented`, HTTP 501 |
| `ListBucketIntelligentTieringConfigurations` | none | Not in the spec: the Intelligent-Tiering archive tiers. Storage classes map to Kythira tiers through lifecycle (task 13). | `NotImplemented`, HTTP 501 |
| `ListBucketInventoryConfigurations` | none | Out of scope: S3 Inventory. | `NotImplemented`, HTTP 501 |
| `ListBucketMetricsConfigurations` | none | Not in the spec: CloudWatch request-metrics filters. Kythira exports its own metrics instead. | `NotImplemented`, HTTP 501 |
| `ListDirectoryBuckets` | none | Out of scope: S3 Express One Zone directory buckets. | `NotImplemented`, HTTP 501 |
| `ListObjectAnnotations` | none | Not in the spec: object annotations, added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `PutBucketAbac` | none | Not in the spec: bucket ABAC (tag-based access to general purpose buckets), added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `PutBucketAccelerateConfiguration` | none | Out of scope: Transfer Acceleration. | `NotImplemented`, HTTP 501 |
| `PutBucketAnalyticsConfiguration` | none | Out of scope: S3 Analytics (storage class analysis). | `NotImplemented`, HTTP 501 |
| `PutBucketIntelligentTieringConfiguration` | none | Not in the spec: the Intelligent-Tiering archive tiers. Storage classes map to Kythira tiers through lifecycle (task 13). | `NotImplemented`, HTTP 501 |
| `PutBucketInventoryConfiguration` | none | Out of scope: S3 Inventory. | `NotImplemented`, HTTP 501 |
| `PutBucketMetricsConfiguration` | none | Not in the spec: CloudWatch request-metrics filters. Kythira exports its own metrics instead. | `NotImplemented`, HTTP 501 |
| `PutBucketRequestPayment` | none | Out of scope: Requester Pays. `GetBucketRequestPayment` answers `BucketOwner`. | `NotImplemented`, HTTP 501 |
| `PutObjectAnnotation` | none | Not in the spec: object annotations, added to S3 after the spec was written. Open question for the owner. | `NotImplemented`, HTTP 501 |
| `RenameObject` | none | Out of scope: S3 Express One Zone directory buckets. | `NotImplemented`, HTTP 501 |
| `SelectObjectContent` | none | Out of scope: S3 Select. | `NotImplemented`, HTTP 501 |
| `UpdateBucketMetadataAnnotationTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `UpdateBucketMetadataInventoryTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `UpdateBucketMetadataJournalTableConfiguration` | none | Out of scope: S3 Metadata, which keeps its tables in S3 Tables. | `NotImplemented`, HTTP 501 |
| `UpdateObjectEncryption` | none | Not in the spec: changing an existing object from SSE-S3 to SSE-KMS in place, added to S3 after the spec was written. Open question for the owner, after task 11. | `NotImplemented`, HTTP 501 |
| `WriteGetObjectResponse` | none | Out of scope: S3 Object Lambda. | `NotImplemented`, HTTP 501 |
