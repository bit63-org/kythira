#!/bin/sh
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Run the Java SDK v2 evidence client on the classpath record_all.sh built
# (`mvn compile dependency:build-classpath`), so the recording run needs no
# network. run_client.sh passes the endpoint last.
set -eu
dir="$(cd "$(dirname "$0")/java-sdk-v2" && pwd)"
exec java -cp "${dir}/target/classes:$(cat "${dir}/target/cp.txt")" evidence.Main "$@"
