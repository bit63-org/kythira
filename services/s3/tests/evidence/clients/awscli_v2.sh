#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The AWS CLI v2's scenario for the S3 wire evidence (run by run_client.sh,
# which passes the endpoint last). The high-level `aws s3` commands most
# people use (mb, cp up and down with multipart, ls, server-side copy,
# presign, rm, rb) and the s3api calls they do not cover.
set -euo pipefail
endpoint=${!#}
aws=("${AWS_CLI:-aws}" --endpoint-url "$endpoint" --no-cli-pager)
work=${EVIDENCE_WORK:?}
# One request at a time, so parts and ranged reads are recorded in order.
printf '[default]\ns3 =\n  max_concurrent_requests = 1\n' >"$work/cli-config"
export AWS_CONFIG_FILE="$work/cli-config"
printf 'hello from the kythira evidence recorder\n' >"$work/hello.txt"
# 17 MiB of a fixed pattern: three parts at the CLI's 8 MiB default.
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * (17 * 1024 * 1024 // 256))' \
  >"$work/large.bin"

"${aws[@]}" s3 mb s3://evidence
"${aws[@]}" s3api head-bucket --bucket evidence
"${aws[@]}" s3 cp "$work/hello.txt" s3://evidence/hello.txt
"${aws[@]}" s3 cp "$work/large.bin" s3://evidence/large.bin
"${aws[@]}" s3api head-object --bucket evidence --key hello.txt >/dev/null
"${aws[@]}" s3api get-object --bucket evidence --key hello.txt --range bytes=0-4 \
  "$work/range.out" >/dev/null
"${aws[@]}" s3 ls s3://evidence/
"${aws[@]}" s3 cp s3://evidence/hello.txt s3://evidence/dir/copy.txt
"${aws[@]}" s3 cp s3://evidence/large.bin "$work/large.out"
cmp "$work/large.bin" "$work/large.out"
url=$("${aws[@]}" s3 presign s3://evidence/hello.txt)
curl -fsS --cacert "$AWS_CA_BUNDLE" "$url" | cmp - "$work/hello.txt"
upload=$("${aws[@]}" s3api create-multipart-upload --bucket evidence --key aborted.bin \
  --query UploadId --output text)
"${aws[@]}" s3api abort-multipart-upload --bucket evidence --key aborted.bin --upload-id "$upload"
"${aws[@]}" s3 rm --recursive s3://evidence/
"${aws[@]}" s3 rb s3://evidence
