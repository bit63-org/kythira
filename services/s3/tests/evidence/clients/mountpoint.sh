#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Mountpoint for Amazon S3's scenario for the S3 wire evidence (run by
# run_client.sh with EVIDENCE_BUCKETS=evidence, since Mountpoint mounts a
# bucket that exists, and EVIDENCE_SYSTEM_CA=1, since its CRT reads only
# the system trust store). Mount, write a small file and a 12 MiB one
# (Mountpoint always uploads with multipart), list, read back, delete,
# unmount. Needs /dev/fuse and root, or a user allowed to mount FUSE.
set -euo pipefail
endpoint=${!#}
work=${EVIDENCE_WORK:?}
mnt="$work/mnt"
mkdir -p "$mnt"
${MOUNT_S3:-mount-s3} evidence "$mnt" --endpoint-url "$endpoint" --region us-east-1 \
  --allow-delete --max-threads 1
trap 'umount "$mnt" 2>/dev/null || fusermount -u "$mnt" 2>/dev/null || true' EXIT
printf 'hello from the kythira evidence recorder\n' >"$mnt/hello.txt"
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * (12 * 1024 * 1024 // 256))' \
  >"$mnt/large.bin"
ls -l "$mnt"
cmp "$mnt/hello.txt" <(printf 'hello from the kythira evidence recorder\n')
head -c 1048576 "$mnt/large.bin" >/dev/null
rm "$mnt/hello.txt" "$mnt/large.bin"
