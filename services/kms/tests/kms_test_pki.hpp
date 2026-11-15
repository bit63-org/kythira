// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A throwaway PKI for kms_node's TLS tests: a CA and leaves with chosen
// subject alternative names, as PEM files in a temporary directory. The
// HSM's tests have the same one (services/hsm/tests/hsm_test_pki.hpp);
// the module boundary keeps the KMS from including it.

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>

namespace kythira::kms::test {

class test_pki {
public:
    struct files {
        std::string cert;
        std::string key;
    };

    test_pki() {
        static std::atomic<unsigned> counter{0};
        std::random_device rd;
        _dir = std::filesystem::temp_directory_path() /
               ("kythira-kms-pki-" + std::to_string(rd()) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(_dir);
        _ca_key.reset(EVP_EC_gen("P-256"));
        if (!_ca_key) {
            throw std::runtime_error("test_pki: no CA key");
        }
        _ca.reset(make(nullptr, _ca_key.get(), "kythira kms test CA", nullptr, true));
        _ca_path = (_dir / "ca.pem").string();
        write_cert(_ca_path, _ca.get());
    }

    ~test_pki() {
        std::error_code ec;
        std::filesystem::remove_all(_dir, ec);
    }

    test_pki(const test_pki&) = delete;
    auto operator=(const test_pki&) -> test_pki& = delete;
    test_pki(test_pki&&) = delete;
    auto operator=(test_pki&&) -> test_pki& = delete;

    [[nodiscard]] auto ca_path() const -> const std::string& { return _ca_path; }
    /// Where the PEM files are: `ca.pem`, and `<name>.pem` / `<name>.key`
    /// for each leaf issued.
    [[nodiscard]] auto dir() const -> const std::filesystem::path& { return _dir; }

    /// A leaf signed by the CA, with `sans` in OpenSSL's config syntax
    /// ("DNS:localhost,IP:127.0.0.1,URI:spiffe://kms/node-1").
    auto issue(const std::string& name, const std::string& sans) -> files {
        const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_EC_gen("P-256"),
                                                                      &EVP_PKEY_free);
        const std::unique_ptr<X509, decltype(&X509_free)> cert(
            make(_ca.get(), key.get(), name.c_str(), sans.c_str(), false), &X509_free);
        files out{(_dir / (name + ".pem")).string(), (_dir / (name + ".key")).string()};
        write_cert(out.cert, cert.get());
        const std::unique_ptr<FILE, file_close> f(std::fopen(out.key.c_str(), "wb"));
        if (!f ||
            PEM_write_PrivateKey(f.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("test_pki: cannot write " + out.key);
        }
        return out;
    }

private:
    struct file_close {
        void operator()(FILE* f) const { std::fclose(f); }
    };
    struct pkey_free {
        void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
    };
    struct x509_free {
        void operator()(X509* p) const { X509_free(p); }
    };

    /// A certificate for `key`, signed by `issuer` (self-signed when null).
    auto make(X509* issuer, EVP_PKEY* key, const char* cn, const char* sans, bool ca) -> X509* {
        X509* cert = X509_new();
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), static_cast<long>(++_serial));
        X509_gmtime_adj(X509_getm_notBefore(cert), -60);
        X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
        X509_set_pubkey(cert, key);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
        X509_set_issuer_name(cert, issuer != nullptr ? X509_get_subject_name(issuer) : name);
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, issuer != nullptr ? issuer : cert, cert, nullptr, nullptr, 0);
        const auto add = [&](int nid, const char* value) {
            X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
            if (ext == nullptr) {
                throw std::runtime_error(std::string("test_pki: bad extension ") + value);
            }
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        };
        add(NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
        add(NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
        if (!ca) {
            add(NID_ext_key_usage, "serverAuth,clientAuth");
            add(NID_subject_alt_name, sans);
        }
        if (X509_sign(cert, issuer != nullptr ? _ca_key.get() : key, EVP_sha256()) == 0) {
            X509_free(cert);
            throw std::runtime_error("test_pki: cannot sign");
        }
        return cert;
    }

    static auto write_cert(const std::string& path, X509* cert) -> void {
        const std::unique_ptr<FILE, file_close> f(std::fopen(path.c_str(), "wb"));
        if (!f || PEM_write_X509(f.get(), cert) != 1) {
            throw std::runtime_error("test_pki: cannot write " + path);
        }
    }

    std::filesystem::path _dir;
    std::unique_ptr<EVP_PKEY, pkey_free> _ca_key;
    std::unique_ptr<X509, x509_free> _ca;
    std::string _ca_path;
    unsigned _serial = 0;
};

}  // namespace kythira::kms::test
