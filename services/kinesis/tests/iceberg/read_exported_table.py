#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Reads a table kinesis_channel_tables_test exported, with pyiceberg.

    KINESIS_TABLES_TEST_EXPORT=/tmp/t kinesis_channel_tables_test
    python3 read_exported_table.py /tmp/t            # the first batch
    python3 read_exported_table.py /tmp/t/second     # after the second

An independent Iceberg implementation reading the manifest list, the
manifests and the Avro data files a channel wrote is the check that they
follow the specification and not just our own reader. The export keeps each
bucket as a directory, so a FileIO maps s3://bucket/key onto it. Needs
`pip install pyiceberg pyarrow fastavro`; not run by CTest.
"""

import json
import os
import sys

from pyiceberg.io import FileIO, InputFile, OutputFile
from pyiceberg.io.pyarrow import PyArrowFileIO
from pyiceberg.table import StaticTable

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")


class ExportFileIO(PyArrowFileIO):
    """s3://bucket/key read from <export>/bucket/key."""

    def _local(self, location: str) -> str:
        for scheme in ("s3://", "s3a://", "s3n://"):
            if location.startswith(scheme):
                return os.path.join(ROOT, location[len(scheme):])
        return location

    def new_input(self, location: str) -> InputFile:
        return super().new_input(self._local(location))

    def new_output(self, location: str) -> OutputFile:
        return super().new_output(self._local(location))


def main() -> int:
    table = StaticTable.from_metadata(
        os.path.join(ROOT, "table.metadata.json"),
        properties={"py-io-impl": f"{__name__}.ExportFileIO"},
    )
    snapshot = table.current_snapshot()
    print("snapshot", snapshot.snapshot_id, "sequence", snapshot.sequence_number)
    print("summary", json.dumps(snapshot.summary.model_dump() if hasattr(snapshot.summary, "model_dump") else dict(snapshot.summary)))
    io = table.io
    for manifest in snapshot.manifests(io):
        print("manifest", manifest.manifest_path, "seq", manifest.sequence_number,
              "added", manifest.added_files_count, "partitions", manifest.partitions)
        for entry in manifest.fetch_manifest_entry(io):
            print("  entry", entry.status, entry.sequence_number, entry.data_file.file_path,
                  entry.data_file.partition, entry.data_file.record_count)
    rows = table.scan().to_arrow().sort_by("id").to_pylist()
    for row in rows:
        print("row", row)
    hour = table.scan(row_filter="event_time >= '2025-11-10T13:00:00+00:00'").to_arrow()
    print("rows from 13:00", hour.column("id").to_pylist())
    return 0


if __name__ == "__main__":
    sys.exit(main())
