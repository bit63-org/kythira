// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The aws-sdk-go-v2 SQS suite against Kythira (run_suite.sh client
// "go"): attributes, typed message attributes, batches, visibility, FIFO
// ordering and deduplication, the modelled QueueDoesNotExist error, purge
// and delete. The SDK checks the MD5 of every body and attribute set, so a
// wrong digest fails the run. Usage: sqs-suite-go ENDPOINT
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func check(ok bool, format string, args ...any) {
	if !ok {
		fmt.Fprintf(os.Stderr, "go suite: "+format+"\n", args...)
		os.Exit(1)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "go suite: %v\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	ctx := context.Background()
	cfg := must(config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1")))
	c := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = aws.String(os.Args[1]) })

	url := must(c.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName:  aws.String("suite-go"),
		Attributes: map[string]string{"VisibilityTimeout": "30"},
	})).QueueUrl
	got := must(c.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String("suite-go")})).QueueUrl
	check(*got == *url, "GetQueueUrl %s != %s", *got, *url)
	attrs := must(c.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: url, AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll},
	})).Attributes
	check(attrs["VisibilityTimeout"] == "30", "attributes %v", attrs)

	must(c.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl: url, MessageBody: aws.String("hello go"),
		MessageAttributes: map[string]types.MessageAttributeValue{
			"color": {DataType: aws.String("String"), StringValue: aws.String("blue")},
			"count": {DataType: aws.String("Number"), StringValue: aws.String("7")},
			"blob":  {DataType: aws.String("Binary"), BinaryValue: []byte{0, 1, 2}},
		},
	}))
	var entries []types.SendMessageBatchRequestEntry
	for i := range 3 {
		entries = append(entries, types.SendMessageBatchRequestEntry{
			Id: aws.String(fmt.Sprintf("e%d", i)), MessageBody: aws.String(fmt.Sprintf("batch-%d", i)),
		})
	}
	sent := must(c.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{QueueUrl: url, Entries: entries}))
	check(len(sent.Successful) == 3, "batch send %d", len(sent.Successful))

	var msgs []types.Message
	for i := 0; i < 10 && len(msgs) < 4; i++ {
		out := must(c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl: url, MaxNumberOfMessages: 10, WaitTimeSeconds: 1,
			MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameAll},
			MessageAttributeNames:       []string{"All"},
		}))
		msgs = append(msgs, out.Messages...)
	}
	check(len(msgs) == 4, "received %d", len(msgs))
	i := slices.IndexFunc(msgs, func(m types.Message) bool { return *m.Body == "hello go" })
	check(i >= 0, "hello go not received")
	hello := msgs[i]
	check(*hello.MessageAttributes["color"].StringValue == "blue", "color attribute")
	check(slices.Equal(hello.MessageAttributes["blob"].BinaryValue, []byte{0, 1, 2}), "binary attribute")
	check(hello.Attributes["ApproximateReceiveCount"] == "1", "receive count %v", hello.Attributes)

	must(c.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl: url, ReceiptHandle: hello.ReceiptHandle, VisibilityTimeout: 0,
	}))
	again := must(c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: url, WaitTimeSeconds: 5})).Messages
	check(len(again) == 1 && *again[0].Body == "hello go", "visibility reset")

	var deletes []types.DeleteMessageBatchRequestEntry
	for _, m := range msgs {
		if *m.Body != "hello go" {
			deletes = append(deletes, types.DeleteMessageBatchRequestEntry{Id: m.MessageId, ReceiptHandle: m.ReceiptHandle})
		}
	}
	del := must(c.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{QueueUrl: url, Entries: deletes}))
	check(len(del.Failed) == 0, "batch delete failed %v", del.Failed)
	must(c.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: again[0].ReceiptHandle}))

	fifo := must(c.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String("suite-go.fifo"), Attributes: map[string]string{"FifoQueue": "true"},
	})).QueueUrl
	for _, n := range []int{0, 1, 2, 0} { // the second f0 is a retry, dropped by deduplication
		must(c.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl: fifo, MessageBody: aws.String(fmt.Sprintf("f%d", n)),
			MessageGroupId: aws.String("g"), MessageDeduplicationId: aws.String(fmt.Sprintf("d%d", n)),
		}))
	}
	var order []string
	for i := 0; i < 10 && len(order) < 3; i++ {
		out := must(c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: fifo, MaxNumberOfMessages: 10, WaitTimeSeconds: 1}))
		for _, m := range out.Messages {
			order = append(order, *m.Body)
			must(c.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: fifo, ReceiptHandle: m.ReceiptHandle}))
		}
	}
	check(slices.Equal(order, []string{"f0", "f1", "f2"}), "FIFO order %v", order)

	_, err := c.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String("suite-go-missing")})
	var missing *types.QueueDoesNotExist
	check(errors.As(err, &missing), "GetQueueUrl of a missing queue: %v", err)

	must(c.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: url, MessageBody: aws.String("to purge")}))
	must(c.PurgeQueue(ctx, &sqs.PurgeQueueInput{QueueUrl: url}))
	left := must(c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: url, WaitTimeSeconds: 1})).Messages
	check(len(left) == 0, "purge left %d", len(left))
	must(c.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: url}))
	must(c.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: fifo}))
}
