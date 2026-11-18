// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The evidence scenario through the AWS SDK for Go v2 (README.md).
// Usage: go run . ENDPOINT
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
)

const (
	queue  = "arn:aws:sqs:us-east-1:123456789012:evidence-queue"
	filter = `{"color":["red",{"prefix":"bl"}],"size":[{"numeric":[">",3]}]}`
)

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func str(dataType, value string) types.MessageAttributeValue {
	return types.MessageAttributeValue{DataType: aws.String(dataType), StringValue: aws.String(value)}
}

func main() {
	ctx := context.Background()
	token := "deadbeefdeadbeefdeadbeefdeadbeef" + strings.Repeat("0", 32)
	cfg := must(config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1")))
	c := sns.NewFromConfig(cfg, func(o *sns.Options) { o.BaseEndpoint = aws.String(os.Args[1]) })

	topic := must(c.CreateTopic(ctx, &sns.CreateTopicInput{
		Name:       aws.String("evidence"),
		Attributes: map[string]string{"DisplayName": "Evidence"},
		Tags:       []types.Tag{{Key: aws.String("team"), Value: aws.String("kythira")}},
	})).TopicArn
	fifo := must(c.CreateTopic(ctx, &sns.CreateTopicInput{
		Name:       aws.String("evidence.fifo"),
		Attributes: map[string]string{"FifoTopic": "true", "ContentBasedDeduplication": "true"},
	})).TopicArn
	must(c.ListTopics(ctx, &sns.ListTopicsInput{}))
	must(c.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: topic}))
	must(c.SetTopicAttributes(ctx, &sns.SetTopicAttributesInput{TopicArn: topic,
		AttributeName: aws.String("DisplayName"), AttributeValue: aws.String("Evidence 2")}))
	queueSub := must(c.Subscribe(ctx, &sns.SubscribeInput{TopicArn: topic,
		Protocol: aws.String("sqs"), Endpoint: aws.String(queue),
		Attributes:            map[string]string{"RawMessageDelivery": "true", "FilterPolicy": filter},
		ReturnSubscriptionArn: true})).SubscriptionArn
	must(c.Subscribe(ctx, &sns.SubscribeInput{TopicArn: topic,
		Protocol: aws.String("http"), Endpoint: aws.String("http://127.0.0.1:9/hook")}))
	must(c.ConfirmSubscription(ctx, &sns.ConfirmSubscriptionInput{TopicArn: topic,
		Token: aws.String(token), AuthenticateOnUnsubscribe: aws.String("true")}))
	must(c.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{TopicArn: topic}))
	must(c.SetSubscriptionAttributes(ctx, &sns.SetSubscriptionAttributesInput{
		SubscriptionArn: queueSub, AttributeName: aws.String("FilterPolicyScope"),
		AttributeValue: aws.String("MessageBody")}))
	must(c.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{
		SubscriptionArn: queueSub}))
	must(c.Publish(ctx, &sns.PublishInput{TopicArn: topic, Subject: aws.String("hello"),
		Message: aws.String("hello, world"),
		MessageAttributes: map[string]types.MessageAttributeValue{
			"color": str("String", "red"),
			"size":  str("Number", "4"),
			"blob": {DataType: aws.String("Binary"),
				BinaryValue: []byte{0, 1, 0xfe, 0xff}},
			"tags": str("String.Array", `["a","b"]`),
		}}))
	must(c.Publish(ctx, &sns.PublishInput{TopicArn: topic, MessageStructure: aws.String("json"),
		Message: aws.String(`{"default":"fallback","sqs":"to queues","http":"to endpoints"}`)}))
	first := must(c.Publish(ctx, &sns.PublishInput{TopicArn: fifo, Message: aws.String("first"),
		MessageGroupId: aws.String("g1")}))
	if first.SequenceNumber == nil {
		log.Fatal("no sequence number from a FIFO topic")
	}
	must(c.PublishBatch(ctx, &sns.PublishBatchInput{TopicArn: fifo,
		PublishBatchRequestEntries: []types.PublishBatchRequestEntry{
			{Id: aws.String("one"), Message: aws.String("second"), MessageGroupId: aws.String("g1")},
			{Id: aws.String("two"), Message: aws.String("third"), MessageGroupId: aws.String("g2"),
				MessageDeduplicationId: aws.String("dedup-3"),
				MessageAttributes: map[string]types.MessageAttributeValue{
					"color": str("String", "blue")}},
		}}))
	must(c.TagResource(ctx, &sns.TagResourceInput{ResourceArn: topic,
		Tags: []types.Tag{{Key: aws.String("env"), Value: aws.String("test")}}}))
	tags := must(c.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{ResourceArn: topic})).Tags
	if len(tags) != 2 {
		log.Fatalf("unexpected tags: %v", tags)
	}
	must(c.UntagResource(ctx, &sns.UntagResourceInput{ResourceArn: topic, TagKeys: []string{"env"}}))
	must(c.Unsubscribe(ctx, &sns.UnsubscribeInput{SubscriptionArn: queueSub}))
	must(c.DeleteTopic(ctx, &sns.DeleteTopicInput{TopicArn: fifo}))
	must(c.DeleteTopic(ctx, &sns.DeleteTopicInput{TopicArn: topic}))
}
