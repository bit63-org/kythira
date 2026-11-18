# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS module's daemon (.kiro/specs/sqs-compatible-queues/ task 11):
# one durable `sqs_node` per container, addressed by compose service name,
# for the migration-path scenario (services/sqs/tests/docker/).
#
# Ubuntu 24.04 because the binary is built on the host against that
# libstdc++ and COPIED in, never rebuilt here, as in
# services/kinesis/docker/kinesis_gateway_node/Dockerfile. No HEALTHCHECK:
# the scenario probes readiness itself, which also sidesteps Podman's
# OCI-format HEALTHCHECK drop.
#
# No capabilities, no privileged or host networking: CLAUDE.md's container
# rules require this to run under rootless Podman.

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

# libatomic1: a clang build links network_simulator's consumers against
# libatomic, which the base image lacks.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libatomic1 \
    && rm -rf /var/lib/apt/lists/*

COPY services/sqs/docker/sqs_node/dist/ /usr/local/bin/

# Fail the image build, naming the library, rather than leave a container
# to exit 127 with nothing in its log if the host build links a shared
# library this image does not carry.
RUN test -x /usr/local/bin/sqs_node; \
    missing="$(ldd /usr/local/bin/sqs_node | sed -n '/not found/p')"; \
    if [ -n "$missing" ]; then echo "sqs_node: $missing" >&2; exit 1; fi

# Raft RPC and the SQS API. See `sqs_node --help`.
EXPOSE 7000 9324

ENTRYPOINT ["/usr/local/bin/sqs_node"]
