// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// aws-sdk-js-v3's scenario for the S3 wire evidence
// (.kiro/specs/s3-compatible-storage/ task 1): bucket lifecycle, a small
// PutObject, HEAD and ranged GET, a multipart upload through lib-storage,
// listings, a copy, a presigned GET, an aborted upload, a multi-object
// delete and the bucket's removal. Default addressing and checksum
// settings; the endpoint is the last argument. Node trusts the recorder's
// CA through NODE_EXTRA_CA_CERTS.
import {
  AbortMultipartUploadCommand, CopyObjectCommand, CreateBucketCommand,
  CreateMultipartUploadCommand, DeleteBucketCommand, DeleteObjectCommand,
  DeleteObjectsCommand, GetObjectCommand, HeadBucketCommand, HeadObjectCommand,
  ListBucketsCommand, ListObjectsV2Command, PutObjectCommand, S3Client,
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import https from "node:https";

const endpoint = process.argv[process.argv.length - 1];
const Bucket = "evidence";
const small = Buffer.from("hello from the kythira evidence recorder\n");
const pattern = (n) => Buffer.from(Uint8Array.from({ length: n }, (_, i) => i & 0xff));

const fetchUrl = (url) => new Promise((resolve, reject) => {
  https.get(url, (res) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("end", () => resolve(Buffer.concat(chunks)));
  }).on("error", reject);
});

const s3 = new S3Client({ endpoint, region: "us-east-1" });
await s3.send(new CreateBucketCommand({ Bucket }));
await s3.send(new HeadBucketCommand({ Bucket }));
await s3.send(new PutObjectCommand({ Bucket, Key: "hello.txt", Body: small, ContentType: "text/plain" }));
await s3.send(new HeadObjectCommand({ Bucket, Key: "hello.txt" }));
const range = await s3.send(new GetObjectCommand({ Bucket, Key: "hello.txt", Range: "bytes=0-4" }));
const got = Buffer.from(await range.Body.transformToByteArray());
if (!got.equals(small.subarray(0, 5))) throw new Error(`ranged GET returned ${got}`);
// 12 MiB at 5 MiB parts, one at a time: three parts in order.
await new Upload({
  client: s3, queueSize: 1, partSize: 5 * 1024 * 1024,
  params: { Bucket, Key: "large.bin", Body: pattern(12 * 1024 * 1024) },
}).done();
await s3.send(new ListObjectsV2Command({ Bucket, Delimiter: "/" }));
await s3.send(new CopyObjectCommand({ Bucket, Key: "copy.txt", CopySource: `${Bucket}/hello.txt` }));
const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket, Key: "copy.txt" }), { expiresIn: 3600 });
if (!(await fetchUrl(url)).equals(small)) throw new Error("presigned GET returned the wrong bytes");
const { UploadId } = await s3.send(new CreateMultipartUploadCommand({ Bucket, Key: "aborted.bin" }));
await s3.send(new AbortMultipartUploadCommand({ Bucket, Key: "aborted.bin", UploadId }));
await s3.send(new DeleteObjectsCommand({ Bucket, Delete: { Objects: [{ Key: "copy.txt" }, { Key: "large.bin" }] } }));
await s3.send(new DeleteObjectCommand({ Bucket, Key: "hello.txt" }));
await s3.send(new DeleteBucketCommand({ Bucket }));
await s3.send(new ListBucketsCommand({}));
s3.destroy();
