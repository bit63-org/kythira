// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.evidence;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;
import software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry;
import software.amazon.awssdk.services.sns.model.Tag;

/** The evidence scenario through aws-sdk-java-v2 (README.md). Usage: JavaSdkV2Client ENDPOINT */
public final class JavaSdkV2Client {
    private static final String TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef" + "0".repeat(32);
    private static final String QUEUE = "arn:aws:sqs:us-east-1:123456789012:evidence-queue";
    private static final String FILTER =
            "{\"color\":[\"red\",{\"prefix\":\"bl\"}],\"size\":[{\"numeric\":[\">\",3]}]}";

    private JavaSdkV2Client() {}

    /** A map in the order given, so a rerun flattens it the same way (Map.of's order is random). */
    private static <V> Map<String, V> ordered(Object... kv) {
        Map<String, V> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            @SuppressWarnings("unchecked")
            V v = (V) kv[i + 1];
            m.put((String) kv[i], v);
        }
        return m;
    }

    private static MessageAttributeValue str(String type, String value) {
        return MessageAttributeValue.builder().dataType(type).stringValue(value).build();
    }

    public static void main(String[] args) {
        try (SnsClient s = SnsClient.builder()
                .endpointOverride(URI.create(args[0]))
                .region(Region.US_EAST_1)
                .httpClient(UrlConnectionHttpClient.create())
                .build()) {
            String topic = s.createTopic(b -> b.name("evidence")
                    .attributes(ordered("DisplayName", "Evidence"))
                    .tags(Tag.builder().key("team").value("kythira").build())).topicArn();
            String fifo = s.createTopic(b -> b.name("evidence.fifo").attributes(ordered(
                    "FifoTopic", "true", "ContentBasedDeduplication", "true"))).topicArn();
            s.listTopics();
            s.getTopicAttributes(b -> b.topicArn(topic));
            s.setTopicAttributes(b -> b.topicArn(topic).attributeName("DisplayName")
                    .attributeValue("Evidence 2"));
            String queueSub = s.subscribe(b -> b.topicArn(topic).protocol("sqs").endpoint(QUEUE)
                    .attributes(ordered("RawMessageDelivery", "true", "FilterPolicy", FILTER))
                    .returnSubscriptionArn(true)).subscriptionArn();
            s.subscribe(b -> b.topicArn(topic).protocol("http").endpoint("http://127.0.0.1:9/hook"));
            s.confirmSubscription(b -> b.topicArn(topic).token(TOKEN).authenticateOnUnsubscribe("true"));
            s.listSubscriptionsByTopic(b -> b.topicArn(topic));
            s.setSubscriptionAttributes(b -> b.subscriptionArn(queueSub)
                    .attributeName("FilterPolicyScope").attributeValue("MessageBody"));
            s.getSubscriptionAttributes(b -> b.subscriptionArn(queueSub));
            s.publish(b -> b.topicArn(topic).subject("hello").message("hello, world")
                    .messageAttributes(ordered(
                            "color", str("String", "red"),
                            "size", str("Number", "4"),
                            "blob", MessageAttributeValue.builder().dataType("Binary")
                                    .binaryValue(SdkBytes.fromByteArray(
                                            new byte[] {0, 1, (byte) 0xfe, (byte) 0xff}))
                                    .build(),
                            "tags", str("String.Array", "[\"a\",\"b\"]"))));
            s.publish(b -> b.topicArn(topic).messageStructure("json").message(
                    "{\"default\":\"fallback\",\"sqs\":\"to queues\",\"http\":\"to endpoints\"}"));
            if (s.publish(b -> b.topicArn(fifo).message("first").messageGroupId("g1"))
                    .sequenceNumber() == null) {
                throw new IllegalStateException("no sequence number from a FIFO topic");
            }
            s.publishBatch(b -> b.topicArn(fifo).publishBatchRequestEntries(
                    PublishBatchRequestEntry.builder().id("one").message("second")
                            .messageGroupId("g1").build(),
                    PublishBatchRequestEntry.builder().id("two").message("third")
                            .messageGroupId("g2").messageDeduplicationId("dedup-3")
                            .messageAttributes(ordered("color", str("String", "blue"))).build()));
            s.tagResource(b -> b.resourceArn(topic)
                    .tags(Tag.builder().key("env").value("test").build()));
            List<Tag> tags = s.listTagsForResource(b -> b.resourceArn(topic)).tags();
            if (tags.size() != 2) {
                throw new IllegalStateException("unexpected tags: " + tags);
            }
            s.untagResource(b -> b.resourceArn(topic).tagKeys("env"));
            s.unsubscribe(b -> b.subscriptionArn(queueSub));
            s.deleteTopic(b -> b.topicArn(fifo));
            s.deleteTopic(b -> b.topicArn(topic));
        }
    }
}
