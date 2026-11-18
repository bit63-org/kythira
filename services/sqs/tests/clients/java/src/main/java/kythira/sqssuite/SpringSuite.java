// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.sqssuite;

import io.awspring.cloud.sqs.listener.SqsMessageListenerContainer;
import io.awspring.cloud.sqs.operations.SqsTemplate;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.messaging.Message;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;

/**
 * Spring Cloud AWS against Kythira: SqsTemplate sends with a header and receives it back on a
 * standard queue, sends into a FIFO queue with a message group, and a SqsMessageListenerContainer
 * consumes a batch and acknowledges (deletes) each message, after which the queue is empty.
 * Usage: SpringSuite ENDPOINT
 */
public final class SpringSuite {
    private SpringSuite() {}

    private static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("spring suite: " + what);
        }
    }

    public static void main(String[] args) throws Exception {
        try (SqsAsyncClient sqs = SqsAsyncClient.builder()
                .endpointOverride(URI.create(args[0]))
                .region(Region.US_EAST_1)
                .build()) {
            String standard = sqs.createQueue(b -> b.queueName("suite-spring")).join().queueUrl();
            String fifo = sqs.createQueue(b -> b.queueName("suite-spring.fifo")
                            .attributes(Map.of(QueueAttributeName.FIFO_QUEUE, "true",
                                    QueueAttributeName.CONTENT_BASED_DEDUPLICATION, "true")))
                    .join()
                    .queueUrl();
            SqsTemplate template = SqsTemplate.builder().sqsAsyncClient(sqs).build();

            // Template round trip, with a custom header carried as a message attribute.
            template.send(to -> to.queue("suite-spring").payload("hello spring").header("color", "blue"));
            Optional<Message<String>> got = template.receive(
                    from -> from.queue("suite-spring").pollTimeout(Duration.ofSeconds(5)), String.class);
            check(got.isPresent(), "template receive came back empty");
            check("hello spring".equals(got.get().getPayload()), "payload " + got.get().getPayload());
            check("blue".equals(got.get().getHeaders().get("color")), "header " + got.get().getHeaders());

            // FIFO: group id from the template, deduplication from the body.
            template.send(to -> to.queue("suite-spring.fifo").payload("first").messageGroupId("g1"));
            template.send(to -> to.queue("suite-spring.fifo").payload("second").messageGroupId("g1"));
            Optional<Message<String>> first = template.receive(
                    from -> from.queue("suite-spring.fifo").pollTimeout(Duration.ofSeconds(5)), String.class);
            check(first.isPresent() && "first".equals(first.get().getPayload()), "FIFO order " + first);
            Optional<Message<String>> second = template.receive(
                    from -> from.queue("suite-spring.fifo").pollTimeout(Duration.ofSeconds(5)), String.class);
            check(second.isPresent() && "second".equals(second.get().getPayload()), "FIFO order " + second);

            // Listener container: every message delivered once and acknowledged.
            Set<String> seen = ConcurrentHashMap.newKeySet();
            CountDownLatch latch = new CountDownLatch(5);
            SqsMessageListenerContainer<String> container = SqsMessageListenerContainer.<String>builder()
                    .sqsAsyncClient(sqs)
                    .queueNames("suite-spring")
                    .configure(o -> o.pollTimeout(Duration.ofSeconds(2)).maxMessagesPerPoll(10))
                    .messageListener(m -> {
                        if (seen.add(m.getPayload())) {
                            latch.countDown();
                        }
                    })
                    .build();
            for (int i = 0; i < 5; ++i) {
                String body = "batch-" + i;
                template.send(to -> to.queue("suite-spring").payload(body));
            }
            container.start();
            try {
                check(latch.await(30, TimeUnit.SECONDS), "listener saw only " + seen);
            } finally {
                container.stop();
            }
            check(seen.size() == 5, "listener saw " + seen);
            // Acknowledged means deleted: nothing comes back once the visibility timeout is gone.
            sqs.setQueueAttributes(b -> b.queueUrl(standard)
                            .attributes(Map.of(QueueAttributeName.VISIBILITY_TIMEOUT, "0")))
                    .join();
            var left = sqs.receiveMessage(b -> b.queueUrl(standard).waitTimeSeconds(1).maxNumberOfMessages(10))
                    .join();
            check(left.messages().isEmpty(), "unacknowledged messages left: " + left.messages());

            sqs.deleteQueue(b -> b.queueUrl(standard)).join();
            sqs.deleteQueue(b -> b.queueUrl(fifo)).join();
        }
    }
}
