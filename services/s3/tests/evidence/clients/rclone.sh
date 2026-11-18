#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# rclone's scenario for the S3 wire evidence (run by run_client.sh, which
# passes the endpoint last): make a bucket, upload a small file and a
# multipart one, list, read back, server-side copy, delete, remove the
# bucket. The remote is configured from the environment with rclone's
# defaults for provider AWS, except a 5 MiB upload cutoff and chunk size so
# a 12 MiB file goes multipart, and one transfer at a time.
set -euo pipefail
endpoint=${!#}
work=${EVIDENCE_WORK:?}
export RCLONE_CONFIG=/dev/null
export RCLONE_CONFIG_EV_TYPE=s3 RCLONE_CONFIG_EV_PROVIDER=AWS RCLONE_CONFIG_EV_ENV_AUTH=true
export RCLONE_CONFIG_EV_ENDPOINT=$endpoint RCLONE_CONFIG_EV_REGION=us-east-1
rc=("${RCLONE:-rclone}" --transfers 1 --checkers 1 --s3-upload-cutoff 5M --s3-chunk-size 5M
    --s3-upload-concurrency 1 --ca-cert "$SSL_CERT_FILE")
printf 'hello from the kythira evidence recorder\n' >"$work/hello.txt"
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * (12 * 1024 * 1024 // 256))' \
  >"$work/large.bin"

"${rc[@]}" mkdir ev:evidence
"${rc[@]}" copyto "$work/hello.txt" ev:evidence/hello.txt
"${rc[@]}" copyto "$work/large.bin" ev:evidence/large.bin
"${rc[@]}" lsl ev:evidence
"${rc[@]}" cat ev:evidence/hello.txt | cmp - "$work/hello.txt"
"${rc[@]}" copyto ev:evidence/hello.txt ev:evidence/dir/copy.txt
"${rc[@]}" deletefile ev:evidence/dir/copy.txt
"${rc[@]}" purge ev:evidence
