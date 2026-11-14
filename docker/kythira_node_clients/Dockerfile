# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# boto3 and the composite-node scenario's mixed workload
# (.kiro/specs/service-colocation/ task 10): mixed_workload.py drives
# DynamoDB, Kinesis and IAM on a three-node kythira_node cluster. Built by
# the docker-kythira-node-image target with the repository as its context.

FROM python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

RUN pip install --no-cache-dir boto3==1.43.100

COPY docker/kythira_node_clients/mixed_workload.py /usr/local/bin/mixed_workload.py

ENTRYPOINT ["python3", "/usr/local/bin/mixed_workload.py"]
