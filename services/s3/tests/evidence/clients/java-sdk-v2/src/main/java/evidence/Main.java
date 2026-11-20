// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package evidence;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;

/**
 * aws-sdk-java-v2's scenario for the S3 wire evidence: bucket lifecycle, a
 * small PutObject, HEAD and ranged GET, an explicit multipart upload (two
 * parts), listings, a copy, a presigned GET, an aborted upload, a
 * multi-object delete and the bucket's removal. Default addressing and
 * checksum settings; the endpoint is the last argument.
 */
public final class Main {
  private static final String BUCKET = "evidence";
  private static final byte[] SMALL =
      "hello from the kythira evidence recorder\n".getBytes(StandardCharsets.UTF_8);

  private Main() {}

  private static byte[] pattern(int size) {
    byte[] out = new byte[size];
    for (int i = 0; i < size; i++) {
      out[i] = (byte) i;
    }
    return out;
  }

  public static void main(String[] args) throws Exception {
    URI endpoint = URI.create(args[args.length - 1]);
    try (S3Client s3 = S3Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1).build();
        S3Presigner presigner =
            S3Presigner.builder().endpointOverride(endpoint).region(Region.US_EAST_1).build()) {
      s3.createBucket(b -> b.bucket(BUCKET));
      s3.headBucket(b -> b.bucket(BUCKET));
      s3.putObject(b -> b.bucket(BUCKET).key("hello.txt").contentType("text/plain"),
          RequestBody.fromBytes(SMALL));
      s3.headObject(b -> b.bucket(BUCKET).key("hello.txt"));
      ResponseBytes<GetObjectResponse> range =
          s3.getObjectAsBytes(b -> b.bucket(BUCKET).key("hello.txt").range("bytes=0-4"));
      if (!Arrays.equals(range.asByteArray(), Arrays.copyOf(SMALL, 5))) {
        throw new IllegalStateException("ranged GET returned the wrong bytes");
      }
      // Two parts: 5 MiB (the minimum) and 1 MiB.
      String upload = s3.createMultipartUpload(b -> b.bucket(BUCKET).key("large.bin")).uploadId();
      byte[] first = pattern(5 * 1024 * 1024);
      byte[] second = pattern(1024 * 1024);
      String e1 = s3.uploadPart(b -> b.bucket(BUCKET).key("large.bin").uploadId(upload).partNumber(1),
          RequestBody.fromBytes(first)).eTag();
      String e2 = s3.uploadPart(b -> b.bucket(BUCKET).key("large.bin").uploadId(upload).partNumber(2),
          RequestBody.fromBytes(second)).eTag();
      s3.completeMultipartUpload(b -> b.bucket(BUCKET).key("large.bin").uploadId(upload)
          .multipartUpload(m -> m.parts(CompletedPart.builder().partNumber(1).eTag(e1).build(),
              CompletedPart.builder().partNumber(2).eTag(e2).build())));
      s3.listObjectsV2(b -> b.bucket(BUCKET).delimiter("/"));
      s3.copyObject(b -> b.sourceBucket(BUCKET).sourceKey("hello.txt")
          .destinationBucket(BUCKET).destinationKey("copy.txt"));
      URL url = presigner.presignGetObject(p -> p.signatureDuration(Duration.ofHours(1))
          .getObjectRequest(g -> g.bucket(BUCKET).key("copy.txt"))).url();
      try (InputStream in = url.openStream()) {
        if (!Arrays.equals(in.readAllBytes(), SMALL)) {
          throw new IllegalStateException("presigned GET returned the wrong bytes");
        }
      }
      String aborted = s3.createMultipartUpload(b -> b.bucket(BUCKET).key("aborted.bin")).uploadId();
      s3.abortMultipartUpload(b -> b.bucket(BUCKET).key("aborted.bin").uploadId(aborted));
      List<ObjectIdentifier> keys = List.of(ObjectIdentifier.builder().key("copy.txt").build(),
          ObjectIdentifier.builder().key("large.bin").build());
      s3.deleteObjects(b -> b.bucket(BUCKET).delete(d -> d.objects(keys)));
      s3.deleteObject(b -> b.bucket(BUCKET).key("hello.txt"));
      s3.deleteBucket(b -> b.bucket(BUCKET));
      s3.listBuckets();
    }
  }
}
