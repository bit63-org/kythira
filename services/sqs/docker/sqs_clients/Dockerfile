# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The client of the SQS migration-path scenario
# (.kiro/specs/sqs-compatible-queues/ task 11): Python with boto3 at the
# version the wire evidence pins (services/sqs/tests/evidence/
# requirements.txt), the scenario's load and the admin tool that announces
# nodes and runs evacuations. Built by the docker-sqs-node-image target with
# the source root as its context.

FROM python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

RUN pip install --no-cache-dir boto3==1.43.100

COPY services/sqs/tests/docker/sqs_path_load.py /usr/local/bin/sqs_path_load.py
COPY services/sqs/tools/sqs_admin.py /usr/local/bin/sqs_admin.py

ENTRYPOINT ["python3"]
