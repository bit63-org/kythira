# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The virtual HSM chaos node (.kiro/specs/virtual-hsm/ task 11b,
# Requirement 13.6): `hsm_node`, the stand-alone daemon, and
# `kythira_node`, so services/hsm/docker/hsm-chaos-compose.yml runs the HSM
# in either layout from one image (its entrypoint picks the binary).
#
# Built like services/ledger/docker/ledger-chaos/Dockerfile: both binaries
# are compiled on the host against Ubuntu 24.04's libstdc++ and COPIED in
# (RocksDB and OpenSSL come statically from vcpkg); the
# docker-hsm-chaos-image target (services/hsm/tests/docker/CMakeLists.txt)
# stages them into dist/. It runs as uid 10001 with a /data volume. No
# capabilities, no privileged or host networking, so it runs under
# rootless Podman as under Docker (CLAUDE.md). Key memory cannot be locked
# without CAP_IPC_LOCK or a raised RLIMIT_MEMLOCK, so the compose file
# allows unlocked key memory: this is a test image.

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home \
        --home-dir /data --shell /usr/sbin/nologin kythira \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 0750 /data

COPY services/hsm/docker/hsm-chaos/dist/hsm_node /usr/local/bin/hsm_node
COPY services/hsm/docker/hsm-chaos/dist/kythira_node /usr/local/bin/kythira_node
# The KMS-layers layout's lone front end reaches the HSM members through the
# PKCS#11 client library, as a host that runs no HSM would.
COPY services/hsm/docker/hsm-chaos/dist/libkythira_pkcs11.so /usr/local/lib/libkythira_pkcs11.so

# Fail the image build, naming the library, rather than leave a container
# to exit 127 with nothing in its log.
RUN missing="$(for b in /usr/local/bin/hsm_node /usr/local/bin/kythira_node \
                          /usr/local/lib/libkythira_pkcs11.so; do \
                 ldd "$b" | sed -n "s|^|$b: |; /not found/p"; done)"; \
    if [ -n "$missing" ]; then echo "$missing" >&2; exit 1; fi; \
    /usr/local/bin/hsm_node --help >/dev/null && /usr/local/bin/kythira_node --help >/dev/null

ENV KYTHIRA_NODE_DATA_DIR=/data

VOLUME /data
USER 10001:10001

# Raft (mutual TLS), the operator API (HTTPS) and the PKCS#11 client
# listener (mutual TLS); in the encrypted-services layout also the KMS,
# DynamoDB and Kinesis APIs (TLS). Configuration is entirely by
# environment; see
# `hsm_node --help`.
EXPOSE 7100 9443 9444 8443 8000 4567

ENTRYPOINT ["/usr/local/bin/hsm_node"]
