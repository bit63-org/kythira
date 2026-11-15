#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Runs one PKCS#11 consumer against libkythira_pkcs11.so
# (.kiro/specs/virtual-hsm/ task 10b, requirement 5.6). Called by
# hsm_pkcs11_consumers_test, which serves the node and sets:
#
#   KYTHIRA_PKCS11_MODULE   the library
#   KYTHIRA_PKCS11_CONF     its configuration (TLS or socket)
#   P11_TOKEN_LABEL, P11_SLOT, P11_USER_PIN, P11_SO_PIN
#   P11_WORK                an empty directory for this consumer
#
# Usage: consumers.sh pkcs11_tool|openssl_provider|p11_kit|go_crypto11|
#                     java_sunpkcs11|pkcs11test
# Exits non-zero, after saying why, when the consumer fails.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mod="${KYTHIRA_PKCS11_MODULE:?}"
: "${KYTHIRA_PKCS11_CONF:?}" "${P11_TOKEN_LABEL:?}" "${P11_SLOT:?}"
: "${P11_USER_PIN:?}" "${P11_SO_PIN:?}" "${P11_WORK:?}"
cd "$P11_WORK"

fail() {
    echo "consumers.sh: $*" >&2
    exit 1
}

# A free TCP port on 127.0.0.1.
free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# --- OpenSC pkcs11-tool -------------------------------------------------------
pkcs11_tool() {
    local t=(pkcs11-tool --module "$mod")
    local u=("${t[@]}" --login --pin "$P11_USER_PIN")
    "${t[@]}" --list-slots | tee slots.txt
    grep -q "token label *: *${P11_TOKEN_LABEL}" slots.txt || fail "no ${P11_TOKEN_LABEL} slot"
    grep -q "token model *: *virtual HSM" slots.txt || fail "token model"
    "${t[@]}" --slot "$P11_SLOT" --list-mechanisms | tee mechs.txt
    grep -q 'ECDSA-SHA256' mechs.txt || fail "no ECDSA-SHA256"
    grep -q 'AES-GCM' mechs.txt || fail "no AES-GCM"

    "${u[@]}" --keypairgen --key-type EC:prime256v1 --id 01 --label tool-ec
    "${u[@]}" --keypairgen --key-type rsa:2048 --id 02 --label tool-rsa
    "${u[@]}" --keygen --key-type AES:32 --id 03 --label tool-aes
    "${u[@]}" --list-objects | tee objects.txt
    for l in tool-ec tool-rsa tool-aes; do
        grep -q "label: *$l" objects.txt || fail "$l not listed"
    done

    printf 'signed by the virtual hsm\n' >data.txt
    "${u[@]}" --sign --id 01 --mechanism ECDSA-SHA256 --input-file data.txt --output-file ec.sig
    "${u[@]}" --verify --id 01 --mechanism ECDSA-SHA256 --input-file data.txt \
        --signature-file ec.sig
    "${u[@]}" --sign --id 02 --mechanism SHA256-RSA-PKCS-PSS --input-file data.txt \
        --output-file rsa.sig
    "${u[@]}" --verify --id 02 --mechanism SHA256-RSA-PKCS-PSS --input-file data.txt \
        --signature-file rsa.sig
    # The public halves verify outside the token too.
    "${t[@]}" --read-object --type pubkey --id 01 --output-file ec.der
    openssl pkey -pubin -inform DER -in ec.der -out ec.pub
    "${u[@]}" --sign --id 01 --mechanism ECDSA-SHA256 --signature-format openssl \
        --input-file data.txt --output-file ec.der.sig
    openssl dgst -sha256 -verify ec.pub -signature ec.der.sig data.txt

    # A sensitive key's value cannot be read.
    if "${u[@]}" --read-object --type secrkey --id 03 --output-file aes.raw 2>/dev/null; then
        fail "read a sensitive AES key's value"
    fi
    "${u[@]}" --delete-object --type secrkey --id 03
    "${u[@]}" --generate-random 32 --output-file random.bin
    [[ $(stat -c %s random.bin) -eq 32 ]] || fail "random bytes"
    # A wrong PIN is refused.
    if "${t[@]}" --login --pin wrong --list-objects >/dev/null 2>&1; then
        fail "a wrong PIN logged in"
    fi
}

# --- OpenSSL 3 with pkcs11-provider -------------------------------------------
openssl_provider() {
    local provider
    provider="$(openssl version -m | sed -n 's/^MODULESDIR: "\(.*\)"$/\1/p')/pkcs11.so"
    [[ -f $provider ]] || fail "pkcs11-provider is not installed at $provider"
    printf '%s' "$P11_USER_PIN" >pin.txt
    cat >openssl.cnf <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $provider
pkcs11-module-path = $mod
pkcs11-module-token-pin = file:$P11_WORK/pin.txt
activate = 1
EOF
    pkcs11-tool --module "$mod" --login --pin "$P11_USER_PIN" \
        --keypairgen --key-type EC:prime256v1 --id 10 --label tls-ec
    local key="pkcs11:token=${P11_TOKEN_LABEL};object=tls-ec;type=private"
    local pub="pkcs11:token=${P11_TOKEN_LABEL};object=tls-ec;type=public"
    export OPENSSL_CONF="$P11_WORK/openssl.cnf"

    openssl pkey -pubin -in "$pub" -pubout -out tls.pub
    printf 'provider\n' >data.txt
    openssl pkeyutl -sign -inkey "$key" -digest sha256 -rawin -in data.txt -out data.sig
    OPENSSL_CONF=/dev/null openssl pkeyutl -verify -pubin -inkey tls.pub -digest sha256 \
        -rawin -in data.txt -sigfile data.sig

    # A self-signed certificate for the token key, and a TLS server using
    # it; a client with only the default provider must complete the
    # handshake and verify the certificate.
    openssl req -new -x509 -key "$key" -subj /CN=localhost -days 1 \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -out tls.pem
    local port
    port="$(free_port)"
    openssl s_server -accept "127.0.0.1:$port" -key "$key" -cert tls.pem -naccept 1 \
        -www >server.log 2>&1 &
    local server=$!
    local up=0
    for _ in $(seq 1 100); do
        if grep -q ACCEPT server.log 2>/dev/null; then
            up=1
            break
        fi
        sleep 0.1
    done
    [[ $up -eq 1 ]] || { cat server.log; fail "s_server did not start"; }
    printf 'GET / HTTP/1.0\r\n\r\n' |
        OPENSSL_CONF=/dev/null openssl s_client -connect "127.0.0.1:$port" \
            -servername localhost -CAfile tls.pem -verify_return_error -tls1_3 \
            -ign_eof >client.log 2>&1 || { cat client.log server.log; fail "handshake failed"; }
    wait "$server" || true
    grep -q 'Verify return code: 0 (ok)' client.log || { cat client.log; fail "not verified"; }
    grep -q 'Protocol *: *TLSv1.3' client.log ||
        grep -q 'New, TLSv1.3' client.log || { cat client.log; fail "not TLS 1.3"; }
}

# --- p11-kit and GnuTLS --------------------------------------------------------
# p11-kit's server exports the token over its RPC and p11-kit-client.so
# loads it in another process, so every call crosses p11-kit's own
# marshalling of the library's answers. (The server takes the module with
# --provider: p11-kit reads no per-user module configuration as root.)
p11_kit() {
    local client
    client="$(pkg-config --variable=p11_module_path p11-kit-1 2>/dev/null ||
        echo /usr/lib/x86_64-linux-gnu/pkcs11)/p11-kit-client.so"
    [[ -f $client ]] || client="/usr/lib/$(uname -m)-linux-gnu/pkcs11/p11-kit-client.so"
    [[ -f $client ]] || fail "p11-kit-client.so not found"
    local token="pkcs11:token=${P11_TOKEN_LABEL}"
    eval "$(p11-kit server --sh --provider "$mod" --name "$P11_WORK/p11-kit.sock" "$token")"
    trap 'kill "${P11_KIT_SERVER_PID:-0}" 2>/dev/null || true' EXIT
    export P11_KIT_SERVER_ADDRESS
    local c=(pkcs11-tool --module "$client")
    "${c[@]}" --list-slots | tee slots.txt
    grep -q "token label *: *${P11_TOKEN_LABEL}" slots.txt || fail "no token through p11-kit"
    "${c[@]}" --login --pin "$P11_USER_PIN" --keypairgen --key-type EC:prime256v1 \
        --id 20 --label p11kit-ec
    printf 'through p11-kit\n' >data.txt
    "${c[@]}" --login --pin "$P11_USER_PIN" --sign --id 20 --mechanism ECDSA-SHA256 \
        --input-file data.txt --output-file data.sig
    "${c[@]}" --login --pin "$P11_USER_PIN" --verify --id 20 --mechanism ECDSA-SHA256 \
        --input-file data.txt --signature-file data.sig

    # GnuTLS loading the library itself: list, generate and sign.
    export GNUTLS_PIN="$P11_USER_PIN"
    local g=(p11tool --provider "$mod")
    "${g[@]}" --list-tokens | tee tokens.txt
    grep -q "Label: ${P11_TOKEN_LABEL}" tokens.txt || fail "p11tool sees no token"
    grep -q 'Manufacturer: Kythira' tokens.txt || fail "p11tool: manufacturer"
    "${g[@]}" --login --generate-privkey=ecdsa --curve=secp256r1 --label gnutls-ec "$token"
    "${g[@]}" --login --list-privkeys "$token" | tee privkeys.txt
    grep -q 'gnutls-ec' privkeys.txt || fail "p11tool did not list its key"
    "${g[@]}" --login --test-sign "${token};object=gnutls-ec"
}

# --- Go: github.com/ThalesGroup/crypto11 ---------------------------------------
go_crypto11() {
    (cd "$here/go" && go build -o "$P11_WORK/crypto11-smoke" .)
    ./crypto11-smoke -module "$mod" -token "$P11_TOKEN_LABEL" -pin "$P11_USER_PIN"
}

# --- Java: SunPKCS11 -----------------------------------------------------------
java_sunpkcs11() {
    # New keys get no usage flag the template does not ask for, and
    # SunPKCS11's templates ask for none, so the configuration names them
    # (as for any HSM with strict defaults; pkcs11/README.md).
    cat >sunpkcs11.cfg <<EOF
name = Kythira
library = $mod
slot = $P11_SLOT
attributes(generate, CKO_PRIVATE_KEY, *) = {
  CKA_SIGN = true
}
attributes(generate, CKO_PUBLIC_KEY, *) = {
  CKA_VERIFY = true
}
attributes(generate, CKO_SECRET_KEY, *) = {
  CKA_ENCRYPT = true
  CKA_DECRYPT = true
}
EOF
    java "$here/java/SunPkcs11Smoke.java" "$P11_WORK/sunpkcs11.cfg" "$P11_USER_PIN"
}

# --- Google's pkcs11test --------------------------------------------------------
# PKCS11TEST names the built binary (hsm-module.yml builds a pinned
# commit). Tests for what the token does not offer by design are filtered
# out, each with its reason, in pkcs11test.filter.
pkcs11test() {
    local bin="${PKCS11TEST:?PKCS11TEST names the pkcs11test binary}"
    # grep finds no line in a filter of comments only, which is no error
    # here (under pipefail it would end the script without a word).
    local filter args=()
    filter="$(grep -v -e '^#' -e '^$' "$here/pkcs11test.filter" | paste -sd: - || true)"
    if [[ -n "$filter" ]]; then
        args+=(--gtest_filter="-${filter}")
    fi
    "$bin" -m "$(basename "$mod")" -l "$(dirname "$mod")" -s "$P11_SLOT" \
        -u "$P11_USER_PIN" -o "$P11_SO_PIN" -w AES-CBC "${args[@]}"
}

case "${1:-}" in
    pkcs11_tool | openssl_provider | p11_kit | go_crypto11 | java_sunpkcs11 | pkcs11test) "$1" ;;
    *) fail "unknown consumer '${1:-}'" ;;
esac
