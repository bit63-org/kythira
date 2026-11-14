# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# kythira_node, the composite daemon (.kiro/specs/service-colocation/
# task 10, Requirement 9.1), with every module the build compiled in; the
# per-service images stay as they are. Staged from the host build by the
# docker-kythira-node-image target (cmd/kythira_node/CMakeLists.txt) into
# docker/kythira_node/dist, with the repository as the build context:
#
#   kythira_node     the daemon; KYTHIRA_SERVICES picks the modules
#   kythira-iam      IAM's admin CLI, when the IAM module is built
#   iam_test_certs   the throwaway test PKI the scenario's compose file
#                    writes, when the IAM module is built
#
# The two IAM tools are optional: an image without the IAM module simply
# lacks them.

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libatomic1 \
    && rm -rf /var/lib/apt/lists/*

COPY docker/kythira_node/dist/ /usr/local/bin/

RUN missing="$(for b in /usr/local/bin/*; do \
                 ldd "$b" | sed -n "s|^|$b: |; /not found/p"; done)"; \
    if [ -n "$missing" ]; then echo "$missing" >&2; exit 1; fi; \
    /usr/local/bin/kythira_node --help >/dev/null

EXPOSE 7100

ENTRYPOINT ["/usr/local/bin/kythira_node"]
