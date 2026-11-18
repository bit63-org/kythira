// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.evidence;

import java.net.URI;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.ChangeMessageVisibilityBatchRequestEntry;
import software.amazon.awssdk.services.sqs.model.DeleteMessageBatchRequestEntry;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.MessageAttributeValue;
import software.amazon.awssdk.services.sqs.model.MessageSystemAttributeName;
import software.amazon.awssdk.services.sqs.model.MessageSystemAttributeNameForSends;
import software.amazon.awssdk.services.sqs.model.MessageSystemAttributeValue;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sqs.model.QueueDoesNotExistException;
import software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry;

/**
 * The evidence scenario through aws-sdk-java-v2. Usage: JavaSdkV2Client ENDPOINT
 *
 * <p>The SDK checks the MD5 digests of bodies, message attributes and system attributes on
 * every send and receive (MessageMD5ChecksumInterceptor), so a digest the stub computes wrongly
 * fails this client.
 */
public final class JavaSdkV2Client {
    private JavaSdkV2Client() {}

    public static void main(String[] args) {
        try (SqsClient sqs = SqsClient.builder()
                .endpointOverride(URI.create(args[0]))
                .region(Region.US_EAST_1)
                .httpClient(UrlConnectionHttpClient.create())
                .build()) {
            String url = sqs.createQueue(b -> b.queueName("evidence")
                    .attributes(Map.of(QueueAttributeName.VISIBILITY_TIMEOUT, "45"))
                    .tags(Map.of("team", "kythira"))).queueUrl();
            sqs.getQueueUrl(b -> b.queueName("evidence"));
            sqs.getQueueAttributes(b -> b.queueUrl(url).attributeNames(QueueAttributeName.ALL));
            sqs.listQueues(b -> b.queueNamePrefix("evi"));
            sqs.sendMessage(b -> b.queueUrl(url).messageBody("hello")
                    .messageAttributes(Map.of(
                            "s", MessageAttributeValue.builder().dataType("String")
                                    .stringValue("text").build(),
                            "n", MessageAttributeValue.builder().dataType("Number.int")
                                    .stringValue("42").build(),
                            "b", MessageAttributeValue.builder().dataType("Binary")
                                    .binaryValue(SdkBytes.fromByteArray(new byte[] {0, 1, 2}))
                                    .build()))
                    .messageSystemAttributesWithStrings(Map.of(
                            MessageSystemAttributeNameForSends.AWS_TRACE_HEADER.toString(),
                            MessageSystemAttributeValue.builder().dataType("String")
                                    .stringValue("Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1")
                                    .build())));
            sqs.sendMessageBatch(b -> b.queueUrl(url).entries(
                    SendMessageBatchRequestEntry.builder().id("one").messageBody("one").build(),
                    SendMessageBatchRequestEntry.builder().id("two").messageBody("two")
                            .messageAttributes(Map.of("k", MessageAttributeValue.builder()
                                    .dataType("String").stringValue("v").build()))
                            .build()));
            List<Message> got = sqs.receiveMessage(b -> b.queueUrl(url).maxNumberOfMessages(10)
                    .waitTimeSeconds(1).visibilityTimeout(30).messageAttributeNames("All")
                    .messageSystemAttributeNames(MessageSystemAttributeName.ALL)).messages();
            if (got.size() != 3 || !"hello".equals(got.get(0).body())) {
                throw new IllegalStateException("unexpected receive: " + got);
            }
            sqs.changeMessageVisibility(b -> b.queueUrl(url)
                    .receiptHandle(got.get(0).receiptHandle()).visibilityTimeout(60));
            sqs.changeMessageVisibilityBatch(b -> b.queueUrl(url).entries(
                    ChangeMessageVisibilityBatchRequestEntry.builder().id("one")
                            .receiptHandle(got.get(1).receiptHandle()).visibilityTimeout(60)
                            .build()));
            sqs.deleteMessage(b -> b.queueUrl(url).receiptHandle(got.get(0).receiptHandle()));
            sqs.deleteMessageBatch(b -> b.queueUrl(url).entries(
                    DeleteMessageBatchRequestEntry.builder().id("one")
                            .receiptHandle(got.get(1).receiptHandle()).build(),
                    DeleteMessageBatchRequestEntry.builder().id("two")
                            .receiptHandle(got.get(2).receiptHandle()).build()));
            sqs.purgeQueue(b -> b.queueUrl(url));
            String fifo = sqs.createQueue(b -> b.queueName("evidence.fifo").attributes(Map.of(
                    QueueAttributeName.FIFO_QUEUE, "true",
                    QueueAttributeName.CONTENT_BASED_DEDUPLICATION, "false"))).queueUrl();
            sqs.sendMessage(b -> b.queueUrl(fifo).messageBody("first").messageGroupId("g1")
                    .messageDeduplicationId("d1"));
            List<Message> fgot = sqs.receiveMessage(b -> b.queueUrl(fifo)
                    .messageSystemAttributeNames(MessageSystemAttributeName.MESSAGE_GROUP_ID)
                    .receiveRequestAttemptId("attempt-1")).messages();
            sqs.deleteMessage(b -> b.queueUrl(fifo).receiptHandle(fgot.get(0).receiptHandle()));
            sqs.deleteQueue(b -> b.queueUrl(fifo));
            sqs.deleteQueue(b -> b.queueUrl(url));
            try {
                sqs.getQueueUrl(b -> b.queueName("evidence"));
                throw new IllegalStateException("GetQueueUrl of a deleted queue succeeded");
            } catch (QueueDoesNotExistException expected) {
                // The query-compatible error code mapped back to the modelled exception.
            }
        }
    }
}
