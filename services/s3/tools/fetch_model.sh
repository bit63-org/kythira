#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Download the S3 botocore model at a botocore release tag into model/,
# regenerate the operation table from it, and print the model's SHA-256 for
# model/README.md. Bump BOTOCORE_VERSION in tools/gen_operations.py to the
# same tag first, so the header names the version it came from.
#
# Usage: services/s3/tools/fetch_model.sh 1.43.126

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <botocore version>" >&2
    exit 2
fi
version="$1"
module="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! grep -qxF "BOTOCORE_VERSION = \"${version}\"" "${module}/tools/gen_operations.py"; then
    echo "set BOTOCORE_VERSION = \"${version}\" in tools/gen_operations.py first" >&2
    exit 2
fi
curl -fsSL -o "${module}/model/s3-2006-03-01.json" \
    "https://raw.githubusercontent.com/boto/botocore/${version}/botocore/data/s3/2006-03-01/service-2.json"
python3 "${module}/tools/gen_operations.py" "${module}/model/s3-2006-03-01.json" \
    "${module}/include/kythira/s3/model/operations.hpp"
cd "${module}/model"
sha256sum s3-2006-03-01.json
