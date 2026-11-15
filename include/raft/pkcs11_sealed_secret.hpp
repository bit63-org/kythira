// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A secret file sealed under a key on a PKCS#11 token
// (.kiro/specs/virtual-hsm/ task 13c, Requirement 10.3): how a node keeps
// its unseal passphrase off disk when what that passphrase protects cannot
// live on the token itself. IAM's STS keys are AES-256-GCM and the CA's
// peer enrollment key is an HMAC key, neither in the common subset the
// YubiHSM 2 and CloudHSM share, so instead the passphrase that derives their
// keys is sealed (raft/pkcs11_envelope.hpp, RSA-OAEP) under a decryption key
// on the token and opened there each time the node starts. The keys it
// derives are still in the node's memory once it runs: the token protects
// the passphrase at rest, it does not hold those keys.
//
// The file is three lines:
//
//     kythira-pkcs11-sealed-secret v1
//     <the key's URI, with module-path and pin-source, never pin-value>
//     <the sealed secret, base64>
//
// so one file says which library, token, PIN file and key open it. A file
// that does not start with the first line is read as before: its first line
// is the secret.

#include <raft/pkcs11_envelope.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_signing_key.hpp>  // shared_module
#include <raft/pkcs11_uri.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::pkcs11 {

inline constexpr std::string_view k_sealed_secret_header = "kythira-pkcs11-sealed-secret v1";

namespace detail {

/// What a sealed secret file's secret is bound to, so a secret sealed for
/// another purpose under the same key does not open as this one.
inline constexpr std::string_view k_sealed_secret_binding = "kythira sealed secret file v1";

[[nodiscard]] inline auto binding_bytes() -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(k_sealed_secret_binding.data()),
            k_sealed_secret_binding.size()};
}

[[nodiscard]] inline auto strip_line_end(std::string line) -> std::string {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    return line;
}

/// The library, token session and key a sealed secret file names.
struct sealed_secret_key {
    module mod;
    session s;
    CK_OBJECT_HANDLE key;
};

[[nodiscard]] inline auto open_sealed_secret_key(uri u) -> sealed_secret_key {
    if (!u.module_path) {
        throw std::invalid_argument("sealed secret key " + u.to_string() + " has no module-path");
    }
    if (!u.object && !u.id) {
        throw std::invalid_argument("sealed secret key " + u.to_string() +
                                    " names no key (object= or id=)");
    }
    u.type = object_type::private_key;
    auto mod = shared_module(*u.module_path);
    auto s = mod.open(u);
    const auto key = s.find(u);
    return {std::move(mod), std::move(s), key};
}

}  // namespace detail

/// The text of a file holding `secret` sealed under the RSA decryption key
/// `key` names (with module-path and pin-source; a pin-value is refused,
/// since the file would then carry what opens it). `oaep` is the hash the
/// seal uses: SHA-256, or SHA-1 for a module that takes only that.
[[nodiscard]] inline auto seal_secret_file(const uri& key, std::string_view secret,
                                           hash_algorithm oaep = hash_algorithm::sha256)
    -> std::string {
    if (key.pin_value) {
        throw std::invalid_argument(
            "a sealed secret file names its PIN by pin-source=, never pin-value=");
    }
    if (!key.pin_source) {
        throw std::invalid_argument("sealed secret key " + key.to_string() +
                                    " needs pin-source= to open it again");
    }
    if (secret.empty() || secret.find_first_of("\r\n") != std::string_view::npos) {
        throw std::invalid_argument("the secret must be one non-empty line");
    }
    auto k = detail::open_sealed_secret_key(key);
    const envelope_key env(k.s, k.key, oaep);
    const auto sealed =
        env.seal(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(secret.data()),
                                               secret.size()),
                 detail::binding_bytes());
    std::string b64(4 * ((sealed.size() + 2) / 3), '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64.data()), sealed.data(),
                                  static_cast<int>(sealed.size()));
    b64.resize(static_cast<std::size_t>(n));
    auto named = key;
    named.type.reset();
    return std::string(k_sealed_secret_header) + "\n" + named.to_string() + "\n" + b64 + "\n";
}

/// Opens the text of a sealed secret file on its token; nullopt when the
/// text is not one (its first line is not the header).
[[nodiscard]] inline auto open_secret_file(std::string_view text) -> std::optional<std::string> {
    std::istringstream in{std::string(text)};
    std::string header;
    std::getline(in, header);
    if (detail::strip_line_end(header) != k_sealed_secret_header) {
        return std::nullopt;
    }
    std::string uri_line;
    std::string b64;
    std::getline(in, uri_line);
    std::getline(in, b64);
    uri_line = detail::strip_line_end(uri_line);
    b64 = detail::strip_line_end(b64);
    if (uri_line.empty() || b64.empty() || b64.size() % 4 != 0) {
        throw std::runtime_error("a sealed secret file needs a key URI and a base64 line");
    }
    const auto key = uri::parse(uri_line);
    if (key.pin_value) {
        throw std::runtime_error("a sealed secret file must not carry pin-value=");
    }
    bytes sealed(b64.size() / 4 * 3);
    const int n = EVP_DecodeBlock(sealed.data(), reinterpret_cast<const unsigned char*>(b64.data()),
                                  static_cast<int>(b64.size()));
    if (n <= 0) {
        throw std::runtime_error("a sealed secret file's last line is not base64");
    }
    std::size_t pad = 0;
    for (auto it = b64.rbegin(); it != b64.rend() && *it == '='; ++it) {
        ++pad;
    }
    sealed.resize(static_cast<std::size_t>(n) - pad);
    auto k = detail::open_sealed_secret_key(key);
    const envelope_key env(k.s, k.key);
    auto plain = env.open(sealed, detail::binding_bytes());
    std::string secret(plain.begin(), plain.end());
    OPENSSL_cleanse(plain.data(), plain.size());
    return secret;
}

/// A secret file's secret: the first line of a plain file, or the secret
/// opened on the token for a sealed one. `flag` names the file in errors.
[[nodiscard]] inline auto read_secret_file(const std::string& path, std::string_view flag)
    -> std::string {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open " + std::string(flag) + " " + path);
    }
    std::string text{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    std::optional<std::string> opened;
    try {
        opened = open_secret_file(text);
    } catch (const std::exception& e) {
        OPENSSL_cleanse(text.data(), text.size());
        throw std::runtime_error(std::string(flag) + " " + path + ": " + e.what());
    }
    if (opened) {
        OPENSSL_cleanse(text.data(), text.size());
        if (opened->empty()) {
            throw std::runtime_error(std::string(flag) + " " + path + " seals an empty secret");
        }
        return std::move(*opened);
    }
    const auto end = text.find('\n');
    auto line = detail::strip_line_end(text.substr(0, end));
    OPENSSL_cleanse(text.data(), text.size());
    if (line.empty()) {
        throw std::runtime_error(std::string(flag) + " " + path + " is empty");
    }
    return line;
}

}  // namespace kythira::pkcs11
