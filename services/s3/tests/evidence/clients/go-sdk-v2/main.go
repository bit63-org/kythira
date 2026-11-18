// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// aws-sdk-go-v2's scenario for the S3 wire evidence
// (.kiro/specs/s3-compatible-storage/ task 1): bucket lifecycle, a small
// PutObject, HEAD and ranged GET, a multipart upload through the upload
// manager, listings, a copy, a presigned GET, an aborted upload, a
// multi-object delete and the bucket's removal. Default addressing and
// checksum settings; the endpoint is the last argument.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const bucket = "evidence"

var small = []byte("hello from the kythira evidence recorder\n")

func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func run(endpoint string) error {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint) })
	b := aws.String(bucket)
	steps := []func() error{
		func() error { _, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: b}); return e },
		func() error { _, e := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: b}); return e },
		func() error {
			_, e := client.PutObject(ctx, &s3.PutObjectInput{Bucket: b, Key: aws.String("hello.txt"),
				Body: bytes.NewReader(small), ContentType: aws.String("text/plain")})
			return e
		},
		func() error {
			_, e := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: b, Key: aws.String("hello.txt")})
			return e
		},
		func() error {
			out, e := client.GetObject(ctx, &s3.GetObjectInput{Bucket: b, Key: aws.String("hello.txt"),
				Range: aws.String("bytes=0-4")})
			if e != nil {
				return e
			}
			defer out.Body.Close()
			got, e := io.ReadAll(out.Body)
			if e == nil && !bytes.Equal(got, small[:5]) {
				e = fmt.Errorf("ranged GET returned %q", got)
			}
			return e
		},
		func() error {
			// 12 MiB at 5 MiB parts, one at a time: three parts in order.
			up := manager.NewUploader(client, func(u *manager.Uploader) {
				u.PartSize = 5 * 1024 * 1024
				u.Concurrency = 1
			})
			_, e := up.Upload(ctx, &s3.PutObjectInput{Bucket: b, Key: aws.String("large.bin"),
				Body: bytes.NewReader(pattern(12 * 1024 * 1024))})
			return e
		},
		func() error {
			_, e := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: b, Delimiter: aws.String("/")})
			return e
		},
		func() error {
			_, e := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: b, Key: aws.String("copy.txt"),
				CopySource: aws.String(bucket + "/hello.txt")})
			return e
		},
		func() error {
			req, e := s3.NewPresignClient(client).PresignGetObject(ctx,
				&s3.GetObjectInput{Bucket: b, Key: aws.String("copy.txt")},
				s3.WithPresignExpires(time.Hour))
			if e != nil {
				return e
			}
			resp, e := http.Get(req.URL)
			if e != nil {
				return e
			}
			defer resp.Body.Close()
			got, e := io.ReadAll(resp.Body)
			if e == nil && !bytes.Equal(got, small) {
				e = fmt.Errorf("presigned GET returned %d %q", resp.StatusCode, got)
			}
			return e
		},
		func() error {
			out, e := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: b,
				Key: aws.String("aborted.bin")})
			if e != nil {
				return e
			}
			_, e = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: b,
				Key: aws.String("aborted.bin"), UploadId: out.UploadId})
			return e
		},
		func() error {
			_, e := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: b, Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{{Key: aws.String("copy.txt")}, {Key: aws.String("large.bin")}}}})
			return e
		},
		func() error {
			_, e := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: b, Key: aws.String("hello.txt")})
			return e
		},
		func() error { _, e := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: b}); return e },
		func() error { _, e := client.ListBuckets(ctx, &s3.ListBucketsInput{}); return e },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[len(os.Args)-1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
