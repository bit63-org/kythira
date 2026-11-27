# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The client-library suites (.kiro/specs/redis-general-data-types/
# Requirement 23.3): redis-py's, go-redis's and ioredis's own tests, at
# pinned releases, unmodified, run by run.sh against a Kythira cluster.
# Which tests run is in redis-py.txt, go-redis.txt and ioredis.txt; the
# only Kythira-specific code is kythira-setup.ts, which points ioredis's
# defaults at the cluster.
#
# Everything that needs the internet happens here, at build time: the
# three checkouts (each verified against its commit), the Python, Go and
# npm dependencies, and the go-redis test binary. At run time the image
# needs only the compose network.
#
# The image runs as root. It is the client, not the server: nothing in it
# listens, and it writes only inside its own throwaway container.

ARG REGISTRY=docker.io/

FROM ${REGISTRY}library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS go-build
ARG GO_REDIS_REF=v9.22.0
ARG GO_REDIS_COMMIT=c7f59a2a950eb5131cc27bfff716d6d3382e4490
RUN git clone --quiet --depth 1 --branch "${GO_REDIS_REF}" \
        https://github.com/redis/go-redis.git /opt/go-redis \
    && test "$(git -C /opt/go-redis rev-parse HEAD)" = "${GO_REDIS_COMMIT}"
WORKDIR /opt/go-redis
RUN CGO_ENABLED=0 go test -c -o /opt/go-redis/go-redis.test .

FROM ${REGISTRY}library/node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
ARG REDIS_PY_REF=v8.0.1
ARG REDIS_PY_COMMIT=7c0fd118c48a7a863d0a0262d858d02c001c4b73
ARG IOREDIS_REF=v5.11.1
ARG IOREDIS_COMMIT=fb224a7609b6d25959e06e31fdab2460d1f75691

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# redis-py: the library from its own checkout, and the test runner's
# plugins at fixed versions.
RUN git clone --quiet --depth 1 --branch "${REDIS_PY_REF}" \
        https://github.com/redis/redis-py.git /opt/redis-py \
    && test "$(git -C /opt/redis-py rev-parse HEAD)" = "${REDIS_PY_COMMIT}" \
    && python3 -m venv /opt/redis-py-venv \
    && /opt/redis-py-venv/bin/pip install --quiet --no-cache-dir \
        /opt/redis-py pytest==9.2.0 pytest-asyncio==1.5.0 pytest-timeout==2.4.0 \
        packaging==26.3

# ioredis: its locked dev dependencies (mocha, ts-node, chai, sinon).
RUN git clone --quiet --depth 1 --branch "${IOREDIS_REF}" \
        https://github.com/redis/ioredis.git /opt/ioredis \
    && test "$(git -C /opt/ioredis rev-parse HEAD)" = "${IOREDIS_COMMIT}" \
    && cd /opt/ioredis && npm ci --no-audit --no-fund --loglevel=error

# go-redis: the test binary, run from its source tree.
COPY --from=go-build /opt/go-redis /opt/go-redis

COPY services/redis/docker/clients/kythira-setup.ts /opt/ioredis/test/helpers/kythira-setup.ts
COPY services/redis/docker/clients/redis-py.txt \
     services/redis/docker/clients/go-redis.txt \
     services/redis/docker/clients/ioredis.txt \
     services/redis/docker/clients/run.sh \
     /opt/kythira/
RUN chmod 0755 /opt/kythira/run.sh

ENTRYPOINT ["/opt/kythira/run.sh"]
