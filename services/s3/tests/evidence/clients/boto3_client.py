#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""boto3's scenario for the S3 wire evidence (run by run_client.sh).

Bucket lifecycle, a small PutObject with the SDK's default checksum, one
with an explicit SHA-256 checksum, HEAD and ranged GET, a multipart upload
through the transfer manager, listings (V2 with a delimiter, V1), a copy,
presigned GETs (boto3's default query signing, then SigV4), an aborted
multipart upload, a multi-object delete and the bucket's removal. Everything goes to the endpoint given as the last
argument with the client's default addressing and checksum settings.
"""

import io
import sys
import urllib.request

import boto3
import botocore.config
from boto3.s3.transfer import TransferConfig

BUCKET = "evidence"
SMALL = b"hello from the kythira evidence recorder\n"
# 17 MiB of a fixed pattern: three parts at the transfer manager's 8 MiB.
LARGE = bytes(range(256)) * (17 * 1024 * 1024 // 256)


def main() -> int:
    endpoint = sys.argv[-1]
    s3 = boto3.client("s3", endpoint_url=endpoint)
    s3.create_bucket(Bucket=BUCKET)
    s3.head_bucket(Bucket=BUCKET)
    s3.get_bucket_location(Bucket=BUCKET)
    s3.put_object(Bucket=BUCKET, Key="hello.txt", Body=SMALL, ContentType="text/plain")
    s3.put_object(Bucket=BUCKET, Key="dir/sha256.txt", Body=SMALL, ChecksumAlgorithm="SHA256")
    s3.head_object(Bucket=BUCKET, Key="hello.txt")
    got = s3.get_object(Bucket=BUCKET, Key="hello.txt", Range="bytes=0-4")["Body"].read()
    assert got == SMALL[:5], got
    s3.upload_fileobj(io.BytesIO(LARGE), BUCKET, "large.bin",
                      Config=TransferConfig(multipart_threshold=8 * 1024 * 1024,
                                            multipart_chunksize=8 * 1024 * 1024,
                                            max_concurrency=1))
    s3.list_objects_v2(Bucket=BUCKET, Prefix="", Delimiter="/")
    s3.list_objects(Bucket=BUCKET)
    s3.copy_object(Bucket=BUCKET, Key="copy.txt", CopySource={"Bucket": BUCKET, "Key": "hello.txt"})
    url = s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": "copy.txt"},
                                    ExpiresIn=3600)
    with urllib.request.urlopen(url) as r:  # noqa: S310 (the recorder, over HTTPS)
        assert r.read() == SMALL
    # The default above is what boto3 chooses for this endpoint; SigV4 query
    # signing has to be asked for.
    v4 = boto3.client("s3", endpoint_url=endpoint,
                      config=botocore.config.Config(signature_version="s3v4"))
    url = v4.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": "copy.txt"},
                                    ExpiresIn=3600)
    with urllib.request.urlopen(url) as r:  # noqa: S310
        assert r.read() == SMALL
    upload = s3.create_multipart_upload(Bucket=BUCKET, Key="aborted.bin")["UploadId"]
    s3.list_multipart_uploads(Bucket=BUCKET)
    s3.abort_multipart_upload(Bucket=BUCKET, Key="aborted.bin", UploadId=upload)
    s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": "copy.txt"},
                                                         {"Key": "dir/sha256.txt"},
                                                         {"Key": "large.bin"}]})
    s3.delete_object(Bucket=BUCKET, Key="hello.txt")
    s3.delete_bucket(Bucket=BUCKET)
    s3.list_buckets()
    return 0


if __name__ == "__main__":
    sys.exit(main())
