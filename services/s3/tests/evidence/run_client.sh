#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Run one evidence client against a fresh recorder and write its evidence.
#
#   run_client.sh NAME OUT.json COMMAND...
#
# The client gets the endpoint URL (https://s3.kythira.test:<port>) as its
# last argument. Credentials are fixed dummies, so the signature is real
# SigV4 but nothing can reach AWS.
#
# The recorder serves HTTPS under a throwaway CA, so clients behave as they
# do against a real endpoint (several sign payloads differently over plain
# HTTP). Each client trusts the CA through its own variable: AWS_CA_BUNDLE
# (AWS CLI, boto3), NODE_EXTRA_CA_CERTS (JS SDK), SSL_CERT_FILE (Go SDK,
# rclone) and a PKCS#12 trust store in JAVA_TOOL_OPTIONS (Java SDK).
# Mountpoint's CRT reads only the system trust store, so with
# EVIDENCE_SYSTEM_CA=1 (root only) the CA is installed there for the run
# and removed after.
#
# Virtual-hosted requests need the endpoint and the bucket's host name to
# resolve to 127.0.0.1; README.md gives the /etc/hosts line.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
name=$1 out=$2
shift 2
py=${EVIDENCE_PYTHON:-python3}
domain=s3.kythira.test
for h in "$domain" "evidence.$domain"; do
  if [[ $(getent hosts "$h" | awk '{print $1}') != 127.0.0.1 ]]; then
    echo "run_client.sh: $h must resolve to 127.0.0.1 (see README.md)" >&2
    exit 2
  fi
done

tmp=$(mktemp -d)
system_ca=/usr/local/share/ca-certificates/kythira-evidence.crt
# shellcheck disable=SC2329  # run by the EXIT trap
cleanup() {
  if [[ -n ${EVIDENCE_SYSTEM_CA:-} && -f $system_ca ]]; then
    rm -f "$system_ca"
    update-ca-certificates --fresh >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=kythira-evidence-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
  -keyout "$tmp/ca.key" -out "$tmp/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$domain" \
  -keyout "$tmp/key.pem" -out "$tmp/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s,DNS:*.%s\nextendedKeyUsage=serverAuth\n' "$domain" "$domain" \
  >"$tmp/ext.cnf"
openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" \
  -CAcreateserial -days 1 -extfile "$tmp/ext.cnf" -out "$tmp/cert.pem" 2>/dev/null

if [[ -n ${EVIDENCE_SYSTEM_CA:-} ]]; then
  cp "$tmp/ca.pem" "$system_ca"
  update-ca-certificates >/dev/null
fi
if command -v keytool >/dev/null; then
  keytool -importcert -noprompt -alias evidence -file "$tmp/ca.pem" \
    -keystore "$tmp/trust.p12" -storetype PKCS12 -storepass evidence >/dev/null 2>&1
fi

buckets=()
for b in ${EVIDENCE_BUCKETS:-}; do buckets+=(--bucket "$b"); done
fifo="$tmp/port"; mkfifo "$fifo"
"$py" "$here/recorder.py" --client "$name" --out "$out" --domain "$domain" \
  --tls-cert "$tmp/cert.pem" --tls-key "$tmp/key.pem" "${buckets[@]}" >"$fifo" &
rec=$!
read -r port <"$fifo"
endpoint="https://$domain:$port"

export AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true
export AWS_CA_BUNDLE="$tmp/ca.pem" NODE_EXTRA_CA_CERTS="$tmp/ca.pem" SSL_CERT_FILE="$tmp/ca.pem"
# The Java client's trust store, and no proxy for the stub's host.
export JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=$tmp/trust.p12 -Djavax.net.ssl.trustStorePassword=evidence -Djavax.net.ssl.trustStoreType=PKCS12"
export NO_PROXY="${NO_PROXY:+$NO_PROXY,}.kythira.test,kythira.test" no_proxy="${no_proxy:+$no_proxy,}.kythira.test,kythira.test"
export EVIDENCE_WORK="$tmp"
rc=0
"$@" "$endpoint" || rc=$?
kill -TERM "$rec"; wait "$rec" || true
exit $rc
