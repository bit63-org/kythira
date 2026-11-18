# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The capture endpoint record_deliveries.py deploys behind a Lambda
function URL: it logs every request SNS sends it, one JSON line each, and
answers 200 so SNS counts the delivery as done.

Function URLs lower-case header names and do not keep their order, so the
recordings have SNS's header values but not its header spelling or order.
"""

import base64
import json


def handler(event, context):  # noqa: ARG001 (Lambda's signature)
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    http = event.get("requestContext", {}).get("http", {})
    print(
        json.dumps(
            {
                "kythira_capture": 1,
                "method": http.get("method"),
                "path": event.get("rawPath"),
                "query": event.get("rawQueryString"),
                "headers": event.get("headers", {}),
                "body": body,
            },
            sort_keys=True,
        )
    )
    return {"statusCode": 200, "body": ""}
