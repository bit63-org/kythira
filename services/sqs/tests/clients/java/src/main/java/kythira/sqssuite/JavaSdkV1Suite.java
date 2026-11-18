// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.sqssuite;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.DeleteMessageBatchRequestEntry;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.MessageAttributeValue;
import com.amazonaws.services.sqs.model.QueueDoesNotExistException;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageBatchRequestEntry;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * aws-sdk-java v1 at 1.12.575, the last release on the query protocol, against Kythira. The SDK checks the MD5
 * of every body and attribute set it sends and receives, so a wrong digest fails the run. Covers
 * attributes, typed message attributes, batches, visibility, FIFO ordering, the modelled
 * QueueDoesNotExist error, purge and delete. Usage: JavaSdkV1Suite ENDPOINT
 */
public final class JavaSdkV1Suite {
    private JavaSdkV1Suite() {}

    private static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("java v1 suite: " + what);
        }
    }

    public static void main(String[] args) {
        AmazonSQS sqs = AmazonSQSClientBuilder.standard()
                .withEndpointConfiguration(new EndpointConfiguration(args[0], "us-east-1"))
                .build();
        try {
            String url = sqs.createQueue(new CreateQueueRequest("suite-java-v1")
                            .addAttributesEntry("VisibilityTimeout", "30"))
                    .getQueueUrl();
            check(url.equals(sqs.getQueueUrl("suite-java-v1").getQueueUrl()), "GetQueueUrl " + url);
            Map<String, String> attrs = sqs.getQueueAttributes(url, List.of("All")).getAttributes();
            check("30".equals(attrs.get("VisibilityTimeout")), "attributes " + attrs);

            sqs.sendMessage(new SendMessageRequest(url, "hello v1")
                    .addMessageAttributesEntry("color",
                            new MessageAttributeValue().withDataType("String").withStringValue("blue"))
                    .addMessageAttributesEntry("count",
                            new MessageAttributeValue().withDataType("Number").withStringValue("7"))
                    .addMessageAttributesEntry("blob", new MessageAttributeValue()
                            .withDataType("Binary")
                            .withBinaryValue(ByteBuffer.wrap("\u0000\u0001".getBytes(StandardCharsets.ISO_8859_1)))));
            List<SendMessageBatchRequestEntry> batch = new ArrayList<>();
            for (int i = 0; i < 3; ++i) {
                batch.add(new SendMessageBatchRequestEntry("e" + i, "batch-" + i));
            }
            check(sqs.sendMessageBatch(url, batch).getSuccessful().size() == 3, "batch send");

            List<Message> got = new ArrayList<>();
            for (int i = 0; i < 10 && got.size() < 4; ++i) {
                got.addAll(sqs.receiveMessage(new ReceiveMessageRequest(url)
                                .withMaxNumberOfMessages(10)
                                .withWaitTimeSeconds(1)
                                .withAttributeNames("All")
                                .withMessageAttributeNames("All"))
                        .getMessages());
            }
            check(got.size() == 4, "received " + got.size());
            Message hello = got.stream().filter(m -> m.getBody().equals("hello v1")).findFirst().orElseThrow();
            check("blue".equals(hello.getMessageAttributes().get("color").getStringValue()), "color");
            check("1".equals(hello.getAttributes().get("ApproximateReceiveCount")), "receive count");

            sqs.changeMessageVisibility(url, hello.getReceiptHandle(), 0);
            List<Message> again = sqs.receiveMessage(new ReceiveMessageRequest(url).withWaitTimeSeconds(5))
                    .getMessages();
            check(again.size() == 1 && again.get(0).getBody().equals("hello v1"), "visibility reset");

            List<DeleteMessageBatchRequestEntry> deletes = new ArrayList<>();
            for (Message m : got) {
                if (m != hello) {
                    deletes.add(new DeleteMessageBatchRequestEntry(m.getMessageId(), m.getReceiptHandle()));
                }
            }
            check(sqs.deleteMessageBatch(url, deletes).getFailed().isEmpty(), "batch delete");
            sqs.deleteMessage(url, again.get(0).getReceiptHandle());

            String fifo = sqs.createQueue(new CreateQueueRequest("suite-java-v1.fifo")
                            .addAttributesEntry("FifoQueue", "true"))
                    .getQueueUrl();
            for (int i = 0; i < 3; ++i) {
                sqs.sendMessage(new SendMessageRequest(fifo, "f" + i)
                        .withMessageGroupId("g")
                        .withMessageDeduplicationId("d" + i));
            }
            // A retry within the deduplication window is accepted and dropped.
            sqs.sendMessage(new SendMessageRequest(fifo, "f0").withMessageGroupId("g").withMessageDeduplicationId("d0"));
            List<String> order = new ArrayList<>();
            for (int i = 0; i < 10 && order.size() < 3; ++i) {
                for (Message m : sqs.receiveMessage(new ReceiveMessageRequest(fifo).withMaxNumberOfMessages(10)
                                .withWaitTimeSeconds(1))
                        .getMessages()) {
                    order.add(m.getBody());
                    sqs.deleteMessage(fifo, m.getReceiptHandle());
                }
            }
            check(order.equals(List.of("f0", "f1", "f2")), "FIFO order " + order);

            try {
                sqs.getQueueUrl("suite-java-v1-missing");
                check(false, "GetQueueUrl of a missing queue succeeded");
            } catch (QueueDoesNotExistException expected) {
                // The modelled error, mapped from the query code.
            }

            sqs.sendMessage(url, "to purge");
            sqs.purgeQueue(new com.amazonaws.services.sqs.model.PurgeQueueRequest(url));
            check(sqs.receiveMessage(new ReceiveMessageRequest(url).withWaitTimeSeconds(1)).getMessages().isEmpty(),
                    "purge left messages");
            sqs.deleteQueue(url);
            sqs.deleteQueue(fifo);
        } finally {
            sqs.shutdown();
        }
    }
}
