// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.sqssuite;

import com.amazon.sqs.javamessaging.AmazonSQSExtendedClient;
import com.amazon.sqs.javamessaging.ExtendedClientConfiguration;
import java.net.URI;
import java.util.List;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;

/**
 * The Amazon SQS Extended Client against Kythira, with an S3 stand-in for the payload bucket:
 * a body over the 256 KiB threshold goes to S3 and travels as a pointer, comes back whole
 * through the extended client, and its S3 object is removed when the message is deleted; a
 * small body stays inline. Usage: ExtendedSuite SQS_ENDPOINT S3_ENDPOINT
 */
public final class ExtendedSuite {
    private ExtendedSuite() {}

    private static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("extended suite: " + what);
        }
    }

    public static void main(String[] args) {
        String bucket = "suite-extended-payloads";
        try (SqsClient raw = SqsClient.builder()
                        .endpointOverride(URI.create(args[0]))
                        .region(Region.US_EAST_1)
                        .httpClient(UrlConnectionHttpClient.create())
                        .build();
                S3Client s3 = S3Client.builder()
                        .endpointOverride(URI.create(args[1]))
                        .region(Region.US_EAST_1)
                        .forcePathStyle(true)
                        .httpClient(UrlConnectionHttpClient.create())
                        .build()) {
            s3.createBucket(b -> b.bucket(bucket));
            SqsClient sqs = new AmazonSQSExtendedClient(
                    raw, new ExtendedClientConfiguration().withPayloadSupportEnabled(s3, bucket));
            String url = sqs.createQueue(b -> b.queueName("suite-extended")).queueUrl();

            String large = "x".repeat(300 * 1024);
            sqs.sendMessage(b -> b.queueUrl(url).messageBody(large));
            // What Kythira stored is the pointer, not the 300 KiB body.
            List<Message> peek = raw.receiveMessage(b -> b.queueUrl(url).waitTimeSeconds(5)
                            .messageAttributeNames("All"))
                    .messages();
            check(peek.size() == 1, "raw receive got " + peek.size());
            check(peek.get(0).body().contains(bucket) && peek.get(0).body().length() < 1024,
                    "stored body is not an S3 pointer: " + peek.get(0).body().length() + " bytes");
            // The library still writes the legacy SQSLargePayloadSize name unless told not to.
            var attrs = peek.get(0).messageAttributes();
            check(attrs.containsKey("ExtendedPayloadSize") || attrs.containsKey("SQSLargePayloadSize"),
                    "no payload size attribute: " + attrs.keySet());
            check(s3.listObjectsV2(b -> b.bucket(bucket)).keyCount() == 1, "payload not in S3");
            raw.changeMessageVisibility(
                    b -> b.queueUrl(url).receiptHandle(peek.get(0).receiptHandle()).visibilityTimeout(0));

            List<Message> got = sqs.receiveMessage(b -> b.queueUrl(url).waitTimeSeconds(5)).messages();
            check(got.size() == 1, "extended receive got " + got.size());
            check(large.equals(got.get(0).body()), "body came back " + got.get(0).body().length() + " bytes");
            sqs.deleteMessage(b -> b.queueUrl(url).receiptHandle(got.get(0).receiptHandle()));
            check(s3.listObjectsV2(b -> b.bucket(bucket)).keyCount() == 0, "payload left in S3 after delete");

            sqs.sendMessage(b -> b.queueUrl(url).messageBody("small"));
            List<Message> small = raw.receiveMessage(b -> b.queueUrl(url).waitTimeSeconds(5)).messages();
            check(small.size() == 1 && "small".equals(small.get(0).body()), "small body not inline");
            raw.deleteMessage(b -> b.queueUrl(url).receiptHandle(small.get(0).receiptHandle()));

            sqs.deleteQueue(b -> b.queueUrl(url));
        }
    }
}
