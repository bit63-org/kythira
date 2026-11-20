# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The boto3 client of the Kinesis container scenario
# (.kiro/specs/kinesis-compatible-streams/ task 7): Python with boto3 at the
# version the wire evidence pins (services/kinesis/tests/evidence/
# requirements.txt), the scenario's producer and polling consumer, and the
# differential tool with its recordings (task 17), and pyiceberg with
# pyarrow to read back the tables case's Iceberg table (task 19), and
# cryptography to open the channel case's envelope-encrypted objects.
# Built by the docker-kinesis-node-image target with the source root as its
# context.

# Debian slim rather than Alpine: pyiceberg's pydantic-core has no
# musllinux wheel at these versions, and building it from source needs a
# Rust toolchain in the image.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

RUN pip install --no-cache-dir --only-binary=:all: \
        boto3==1.43.100 pyiceberg==0.10.0 pyarrow==21.0.0 cryptography==44.0.0

COPY services/kinesis/tests/docker/kinesis_e2e.py /usr/local/bin/kinesis_e2e.py
# Task 17: the differential tool and the AWS recordings it replays (run with
# --entrypoint python3).
COPY services/kinesis/tests/differential/kinesis_differential.py /usr/local/bin/kinesis_differential.py
COPY services/kinesis/tests/differential/recordings/ /usr/local/share/kinesis-diff/

ENTRYPOINT ["python3", "/usr/local/bin/kinesis_e2e.py"]
