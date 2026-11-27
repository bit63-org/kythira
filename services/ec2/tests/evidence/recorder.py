#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""A recording EC2 stub: what clients put on the wire.

.kiro/specs/ec2-compatible-api/ task 1 ("recorded wire evidence ... from a
recording stub"). Each client in clients/ runs one scripted scenario against
this stub; the stub answers just enough of the EC2 API for the scenario to
finish (VPCs, subnets, volumes, instances and tags kept in memory) and
records every request it receives, normalised so a rerun with the same
client version produces the same file:

- the request line, the HTTP version and every header, with the values that
  change per call (signature, date, invocation id) replaced by a placeholder
  that still shows the value's shape;
- the form body as an ordered list of [name, value] pairs, exactly as the
  client flattened it (`InstanceId.1`, `Filter.1.Value.2`,
  `BlockDeviceMapping.1.Ebs.VolumeSize`, `TagSpecification.1.Tag.1.Key`,
  ...), since the flattening is what the EC2 query codec has to accept;
- a ClientToken the client generated itself (a random UUID, which every
  SDK and the CLI send when the caller gives none) replaced by `<uuid>`,
  and then the body's hash by `<varies>`;
- whether the client signed the payload (`x-amz-content-sha256`) and which
  headers it signed.

It answers in EC2's XML: `<ActionResponse xmlns=...><requestId>` and lists
of `<item>`, and errors as `<Response><Errors><Error>`. Three answers are
deliberate errors, and the clients expect them: `DryRun=true` gets
`DryRunOperation` (HTTP 412), `CreateSecurityGroup` gets
`UnsupportedOperation` (what Requirement 14.1 has Kythira answer), and an
unscripted action gets `InvalidAction`.

    recorder.py --port 0 --out FILE --client NAME   (prints the port)

The process records until it receives SIGTERM or SIGINT, then writes FILE.
"""

import argparse
import hashlib
import http.server
import json
import re
import signal
import sys
import threading
import urllib.parse
from xml.sax.saxutils import escape

FORM_CT = "application/x-www-form-urlencoded"
ACCOUNT = "123456789012"
REGION = "us-east-1"
ZONE = "us-east-1a"
NS = "http://ec2.amazonaws.com/doc/2016-11-15/"
REQUEST_ID = "00000000-0000-0000-0000-000000000000"
TIME = "2026-11-27T00:00:00.000Z"
# What DescribeVolumes answers MaxResults with on the first page: the
# scenario reads a second page with the token.
PAGE_TOKEN = "evidence-page-2"

VOLATILE = {
    "x-amz-date": "<amz-date>",
    "amz-sdk-invocation-id": "<uuid>",
    "x-amz-security-token": "<token>",
    "date": "<date>",
}
AUTH_RE = re.compile(r"Signature=[0-9a-f]+")
# Every client fills ClientToken with a random UUID when the caller gives
# none (the model's idempotencyToken trait), so the token varies per run.
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CRED_DATE_RE = re.compile(r"Credential=([^/]+)/\d{8}/")
STATE_CODES = {"pending": 0, "running": 16, "shutting-down": 32, "terminated": 48,
               "stopping": 64, "stopped": 80}


def ec2_id(prefix, n):
    """EC2's 17-hex-digit shape, as the design's identifiers render."""
    return f"{prefix}-0{n:016x}"


def flat_list(form, name):
    """`name.N` values in N order."""
    out, n = [], 1
    while f"{name}.{n}" in form:
        out.append(form[f"{name}.{n}"])
        n += 1
    return out


def tags_of(form, prefix):
    """`prefix.N.Key` / `.Value` as a dict, in order."""
    out, n = {}, 1
    while f"{prefix}.{n}.Key" in form:
        out[form[f"{prefix}.{n}.Key"]] = form.get(f"{prefix}.{n}.Value", "")
        n += 1
    return out


def tag_specs(form):
    """`TagSpecification.N.ResourceType` with its `.Tag.M` set."""
    out, n = {}, 1
    while f"TagSpecification.{n}.ResourceType" in form:
        out[form[f"TagSpecification.{n}.ResourceType"]] = tags_of(form, f"TagSpecification.{n}.Tag")
        n += 1
    return out


def tag_set(tags):
    return "<tagSet>" + "".join(
        f"<item><key>{escape(k)}</key><value>{escape(v)}</value></item>"
        for k, v in tags.items()) + "</tagSet>"


class Stub:
    """VPCs, subnets, volumes, instances and tags, for the scripted scenario."""

    def __init__(self):
        self.lock = threading.Lock()
        self.next = 1
        self.vpcs, self.subnets, self.volumes, self.instances = {}, {}, {}, {}
        self.tags = {}  # resource id -> {key: value}
        self.tokens = {}  # ClientToken -> answer

    def new_id(self, prefix):
        rid = ec2_id(prefix, self.next)
        self.next += 1
        return rid

    def handle(self, action, form):
        with self.lock:
            if form.get("DryRun") == "true":
                return 412, ("DryRunOperation",
                             "Request would have succeeded, but DryRun flag is set.")
            token = form.get("ClientToken")
            if token and (action, token) in self.tokens:
                return self.tokens[(action, token)]
            answer = self._handle(action, form)
            if token:
                self.tokens[(action, token)] = answer
            return answer

    def vpc_xml(self, vid):
        v = self.vpcs[vid]
        return (f"<vpcId>{vid}</vpcId><ownerId>{ACCOUNT}</ownerId><state>{v['state']}</state>"
                f"<cidrBlock>{v['cidr']}</cidrBlock><cidrBlockAssociationSet><item>"
                f"<cidrBlock>{v['cidr']}</cidrBlock><associationId>{v['assoc']}</associationId>"
                "<cidrBlockState><state>associated</state></cidrBlockState></item>"
                "</cidrBlockAssociationSet><dhcpOptionsId>default</dhcpOptionsId>"
                "<instanceTenancy>default</instanceTenancy><isDefault>false</isDefault>"
                + tag_set(self.tags.get(vid, {})))

    def volume_xml(self, vid):
        v = self.volumes[vid]
        att = ""
        if v.get("instance"):
            att = (f"<item><volumeId>{vid}</volumeId><instanceId>{v['instance']}</instanceId>"
                   f"<device>{v['device']}</device><status>attached</status>"
                   f"<attachTime>{TIME}</attachTime>"
                   "<deleteOnTermination>false</deleteOnTermination></item>")
        return (f"<volumeId>{vid}</volumeId><size>{v['size']}</size><snapshotId/>"
                f"<availabilityZone>{v['zone']}</availabilityZone><status>{v['state']}</status>"
                f"<createTime>{TIME}</createTime><attachmentSet>{att}</attachmentSet>"
                f"<volumeType>{v['type']}</volumeType><encrypted>true</encrypted>"
                "<multiAttachEnabled>false</multiAttachEnabled>"
                + tag_set(self.tags.get(vid, {})))

    def instance_xml(self, iid):
        i = self.instances[iid]
        return (f"<instanceId>{iid}</instanceId><imageId>{i['image']}</imageId>"
                f"<instanceState><code>{STATE_CODES[i['state']]}</code><name>{i['state']}</name>"
                f"</instanceState><privateDnsName/><dnsName/><amiLaunchIndex>{i['index']}"
                f"</amiLaunchIndex><instanceType>{i['type']}</instanceType>"
                f"<launchTime>{TIME}</launchTime><placement><availabilityZone>{ZONE}"
                "</availabilityZone><tenancy>default</tenancy></placement>"
                f"<monitoring><state>disabled</state></monitoring><subnetId>{i['subnet']}"
                f"</subnetId><vpcId>{i['vpc']}</vpcId><privateIpAddress>{i['ip']}"
                "</privateIpAddress><architecture>x86_64</architecture>"
                "<rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/xvda</rootDeviceName>"
                "<blockDeviceMapping/><virtualizationType>hvm</virtualizationType>"
                "<hypervisor>xen</hypervisor><groupSet/><networkInterfaceSet/>"
                + tag_set(self.tags.get(iid, {})))

    def state_changes(self, ids, new_state):
        out = []
        for iid in ids:
            i = self.instances[iid]
            old, i["state"] = i["state"], new_state
            out.append(f"<item><instanceId>{iid}</instanceId><currentState><code>"
                       f"{STATE_CODES[new_state]}</code><name>{new_state}</name></currentState>"
                       f"<previousState><code>{STATE_CODES[old]}</code><name>{old}</name>"
                       "</previousState></item>")
        return "<instancesSet>" + "".join(out) + "</instancesSet>"

    def _handle(self, action, f):  # noqa: C901 (one branch per scripted action)
        if action == "DescribeRegions":
            return 200, (f"<regionInfo><item><regionName>{REGION}</regionName>"
                         f"<regionEndpoint>ec2.{REGION}.amazonaws.com</regionEndpoint>"
                         "<optInStatus>opt-in-not-required</optInStatus></item></regionInfo>")
        if action == "DescribeAvailabilityZones":
            return 200, (f"<availabilityZoneInfo><item><zoneName>{ZONE}</zoneName>"
                         f"<zoneState>available</zoneState><regionName>{REGION}</regionName>"
                         "<zoneId>use1-az1</zoneId><zoneType>availability-zone</zoneType>"
                         "<optInStatus>opt-in-not-required</optInStatus><messageSet/>"
                         "</item></availabilityZoneInfo>")
        if action == "CreateVpc":
            vid = self.new_id("vpc")
            self.vpcs[vid] = {"cidr": f.get("CidrBlock", ""), "state": "available",
                              "assoc": self.new_id("vpc-cidr-assoc")}
            self.tags[vid] = tag_specs(f).get("vpc", {})
            return 200, f"<vpc>{self.vpc_xml(vid)}</vpc>"
        if action == "DescribeVpcs":
            ids = flat_list(f, "VpcId") or sorted(self.vpcs)
            return 200, "<vpcSet>" + "".join(
                f"<item>{self.vpc_xml(v)}</item>" for v in ids if v in self.vpcs) + "</vpcSet>"
        if action == "CreateSubnet":
            sid = self.new_id("subnet")
            self.subnets[sid] = {"vpc": f.get("VpcId"), "cidr": f.get("CidrBlock")}
            return 200, (f"<subnet><subnetId>{sid}</subnetId><state>available</state>"
                         f"<vpcId>{f.get('VpcId')}</vpcId><cidrBlock>{f.get('CidrBlock')}"
                         "</cidrBlock><availableIpAddressCount>251</availableIpAddressCount>"
                         f"<availabilityZone>{f.get('AvailabilityZone', ZONE)}</availabilityZone>"
                         "<defaultForAz>false</defaultForAz><mapPublicIpOnLaunch>false"
                         f"</mapPublicIpOnLaunch><ownerId>{ACCOUNT}</ownerId></subnet>")
        if action == "CreateVolume":
            vid = self.new_id("vol")
            self.volumes[vid] = {"size": f.get("Size", "8"), "zone": f.get("AvailabilityZone"),
                                 "type": f.get("VolumeType", "gp3"), "state": "available"}
            self.tags[vid] = tag_specs(f).get("volume", {})
            return 200, self.volume_xml(vid)
        if action == "DescribeVolumes":
            ids = flat_list(f, "VolumeId") or sorted(self.volumes)
            ids = [v for v in ids if v in self.volumes]
            nxt = ""
            if "MaxResults" in f and "NextToken" not in f and len(ids) > 1:
                ids, nxt = ids[:1], f"<nextToken>{PAGE_TOKEN}</nextToken>"
            elif f.get("NextToken") == PAGE_TOKEN:
                ids = ids[1:]
            return 200, "<volumeSet>" + "".join(
                f"<item>{self.volume_xml(v)}</item>" for v in ids) + "</volumeSet>" + nxt
        if action == "RunInstances":
            count = int(f.get("MaxCount", "1"))
            specs = tag_specs(f)
            subnet = f.get("SubnetId", "")
            res = self.new_id("r")
            ids = []
            for n in range(count):
                iid = self.new_id("i")
                self.instances[iid] = {"image": f.get("ImageId"), "type": f.get("InstanceType"),
                                       "subnet": subnet, "index": n, "state": "pending",
                                       "vpc": self.subnets.get(subnet, {}).get("vpc", ""),
                                       "ip": f"10.0.1.{10 + n}"}
                self.tags[iid] = specs.get("instance", {})
                ids.append(iid)
            return 200, (f"<reservationId>{res}</reservationId><ownerId>{ACCOUNT}</ownerId>"
                         "<groupSet/><instancesSet>" + "".join(
                             f"<item>{self.instance_xml(i)}</item>" for i in ids)
                         + "</instancesSet>")
        if action == "DescribeInstances":
            ids = flat_list(f, "InstanceId") or sorted(self.instances)
            for i in ids:
                if self.instances.get(i, {}).get("state") == "pending":
                    self.instances[i]["state"] = "running"
            items = "".join(f"<item>{self.instance_xml(i)}</item>"
                            for i in ids if i in self.instances)
            return 200, ("<reservationSet><item><reservationId>" + ec2_id("r", 0)
                         + f"</reservationId><ownerId>{ACCOUNT}</ownerId><groupSet/>"
                         f"<instancesSet>{items}</instancesSet></item></reservationSet>")
        if action == "CreateTags":
            for rid in flat_list(f, "ResourceId"):
                self.tags.setdefault(rid, {}).update(tags_of(f, "Tag"))
            return 200, "<return>true</return>"
        if action == "DeleteTags":
            for rid in flat_list(f, "ResourceId"):
                for k in tags_of(f, "Tag"):
                    self.tags.get(rid, {}).pop(k, None)
            return 200, "<return>true</return>"
        if action == "DescribeTags":
            kinds = {"vpc": "vpc", "vol": "volume", "i": "instance", "subnet": "subnet"}
            items = []
            for rid in sorted(self.tags):
                for k, v in self.tags[rid].items():
                    kind = kinds.get(rid.split("-")[0], "instance")
                    items.append(f"<item><resourceId>{rid}</resourceId><resourceType>{kind}"
                                 f"</resourceType><key>{escape(k)}</key><value>{escape(v)}"
                                 "</value></item>")
            return 200, "<tagSet>" + "".join(items) + "</tagSet>"
        if action in ("AttachVolume", "DetachVolume"):
            vid = f.get("VolumeId")
            if vid not in self.volumes:
                return 400, ("InvalidVolume.NotFound", f"The volume '{vid}' does not exist.")
            v = self.volumes[vid]
            if action == "AttachVolume":
                v.update(instance=f.get("InstanceId"), device=f.get("Device"), state="in-use")
                status = "attaching"
            else:
                status = "detaching"
            out = (f"<volumeId>{vid}</volumeId><instanceId>{v.get('instance')}</instanceId>"
                   f"<device>{v.get('device')}</device><status>{status}</status>"
                   f"<attachTime>{TIME}</attachTime>")
            if action == "DetachVolume":
                v.update(instance=None, state="available")
            return 200, out
        if action == "StopInstances":
            return 200, self.state_changes(flat_list(f, "InstanceId"), "stopping")
        if action == "StartInstances":
            return 200, self.state_changes(flat_list(f, "InstanceId"), "pending")
        if action == "TerminateInstances":
            return 200, self.state_changes(flat_list(f, "InstanceId"), "shutting-down")
        if action == "CreateSecurityGroup":
            return 400, ("UnsupportedOperation",
                         "Security groups are not supported by this endpoint.")
        if action in ("DeleteVolume", "DeleteSubnet", "DeleteVpc"):
            table, key = {"DeleteVolume": (self.volumes, "VolumeId"),
                          "DeleteSubnet": (self.subnets, "SubnetId"),
                          "DeleteVpc": (self.vpcs, "VpcId")}[action]
            table.pop(f.get(key), None)
            return 200, "<return>true</return>"
        return 400, ("InvalidAction", f"The action {action} is not valid for this web service.")


def response_xml(action, status, result):
    head = '<?xml version="1.0" encoding="UTF-8"?>\n'
    if status != 200:
        code, message = result
        return (f"{head}<Response><Errors><Error><Code>{code}</Code>"
                f"<Message>{escape(message)}</Message></Error></Errors>"
                f"<RequestID>{REQUEST_ID}</RequestID></Response>")
    return (f'{head}<{action}Response xmlns="{NS}"><requestId>{REQUEST_ID}</requestId>'
            f"{result}</{action}Response>")


def normalise_headers(items):
    out = []
    for name, value in items:
        low = name.lower()
        if low in VOLATILE:
            value = VOLATILE[low]
        elif low == "authorization":
            value = CRED_DATE_RE.sub(r"Credential=\1/<yyyymmdd>/", AUTH_RE.sub(
                "Signature=<hex>", value))
        elif low == "host":
            value = re.sub(r":\d+$", ":<port>", value)
        elif low in ("user-agent", "x-amz-user-agent"):
            value = re.sub(r"os/(linux|Linux)#\S+", r"os/\1#<kernel>", value)
            value = re.sub(r"(os/linux)/\S+", r"\1/<kernel>", value)
            # botocore lists its feature ids (m/...) in set order, which
            # changes between runs; sort them so a rerun is identical.
            value = re.sub(r"\bm/([A-Za-z0-9,]+)",
                           lambda m: "m/" + ",".join(sorted(m.group(1).split(","))), value)
        elif low == "x-amz-content-sha256" and re.fullmatch(r"[0-9a-f]{64}", value):
            value = "<sha256-hex>"
        out.append([name, value])
    return out


class Recorder:
    def __init__(self, client):
        self.client = client
        self.entries = []
        self.lock = threading.Lock()
        self.stub = Stub()
        self.done = threading.Event()

    def record(self, entry):
        with self.lock:
            self.entries.append(entry)

    def document(self):
        return {"client": self.client, "requests": self.entries,
                "summary": {"operations": [e["operation"] for e in self.entries],
                            "content_types": sorted({e["content_type"] for e in self.entries}),
                            "http_versions": sorted({e["http_version"] for e in self.entries})}}


def make_handler(rec):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802 (http.server's naming)
            length = int(self.headers.get("Content-Length", "0") or 0)
            if self.headers.get("Expect", "").lower() == "100-continue":
                self.send_response_only(100)
                self.end_headers()
            raw = self.rfile.read(length) if length else b""
            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            pairs = urllib.parse.parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
            form = dict(pairs)
            recorded = [[k, "<uuid>" if k == "ClientToken" and UUID_RE.match(v) else v]
                        for k, v in pairs]
            varies = recorded != [list(p) for p in pairs]
            action = form.get("Action", "")
            status, result = rec.stub.handle(action, form)
            rec.record({
                "operation": action,
                "method": self.command,
                "path": self.path,
                "http_version": self.request_version,
                "content_type": ct,
                "content_type_header": self.headers.get("Content-Type"),
                "headers": normalise_headers(self.headers.items()),
                "body_sha256": "<varies>" if varies else
                (hashlib.sha256(raw).hexdigest() if raw else None),
                "form": recorded,
                "response_status": status,
                "response_code": None if status == 200 else result[0],
            })
            payload = response_xml(action, status, result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/xml;charset=UTF-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("x-amzn-RequestId", REQUEST_ID)
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", required=True)
    args = ap.parse_args()
    rec = Recorder(args.client)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(rec))
    print(srv.server_address[1], flush=True)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: rec.done.set())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    rec.done.wait()
    srv.shutdown()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec.document(), f, indent=1)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
