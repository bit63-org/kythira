// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.evidence;

import com.amazon.sqs.javamessaging.ProviderConfiguration;
import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import jakarta.jms.MessageConsumer;
import jakarta.jms.MessageProducer;
import jakarta.jms.Queue;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;
import java.net.URI;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * The evidence scenario through the Amazon SQS Java Messaging Library: a JMS producer sends a
 * text message with a property, a consumer receives it with client acknowledgement and
 * acknowledges it. Usage: JmsClient ENDPOINT
 */
public final class JmsClient {
    private JmsClient() {}

    public static void main(String[] args) throws Exception {
        SqsClient sqs = SqsClient.builder()
                .endpointOverride(URI.create(args[0]))
                .region(Region.US_EAST_1)
                .httpClient(UrlConnectionHttpClient.create())
                .build();
        SQSConnectionFactory factory =
                new SQSConnectionFactory(new ProviderConfiguration().withNumberOfMessagesToPrefetch(1), sqs);
        try (SQSConnection connection = factory.createConnection()) {
            if (!connection.getWrappedAmazonSQSClient().queueExists("evidence-jms")) {
                connection.getWrappedAmazonSQSClient().createQueue("evidence-jms");
            }
            Session session = connection.createSession(false, Session.CLIENT_ACKNOWLEDGE);
            Queue queue = session.createQueue("evidence-jms");
            MessageProducer producer = session.createProducer(queue);
            TextMessage out = session.createTextMessage("hello jms");
            out.setStringProperty("color", "blue");
            out.setIntProperty("count", 7);
            producer.send(out);
            MessageConsumer consumer = session.createConsumer(queue);
            connection.start();
            TextMessage in = (TextMessage) consumer.receive(5000);
            if (in == null || !"hello jms".equals(in.getText())
                    || !"blue".equals(in.getStringProperty("color"))) {
                throw new IllegalStateException("unexpected JMS receive: " + in);
            }
            in.acknowledge();
            connection.stop();
            sqs.deleteQueue(b -> b.queueUrl(sqs.getQueueUrl(g -> g.queueName("evidence-jms")).queueUrl()));
        }
    }
}
