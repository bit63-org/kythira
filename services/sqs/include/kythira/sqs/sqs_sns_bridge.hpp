// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_sns_bridge.hpp
/// @brief Deliveries from real Amazon SNS (`.kiro/specs/sqs-compatible-queues/`
///        task 9, Requirement 10.1).
///
/// SNS cannot deliver to a queue outside AWS, but it can deliver to an
/// HTTPS endpoint. The bridge is that endpoint: subscribe
/// `https://<sqs endpoint>/sns-bridge/<account>/<queue>` to a topic (as an
/// `https` subscription, without raw message delivery, so every request is
/// signed) and the bridge
///
/// - confirms the subscription by fetching its `SubscribeURL`;
/// - checks every request's SNS signature (SignatureVersion 1, SHA1withRSA,
///   or 2, SHA256withRSA) against the signing certificate, fetched only
///   from an allowed host (`sns.<region>.amazonaws.com` by default) over
///   HTTPS and cached;
/// - enqueues each notification as SNS's own SQS delivery would: the JSON
///   envelope as the body, or with raw delivery the message itself with its
///   message attributes as SQS message attributes.
///
/// A queue takes deliveries only when its owner says so, with tags:
///
/// - `kythira:sns-bridge-topics`: the topic ARNs it takes, comma-separated,
///   or `*` for any topic of its own account. The tag stands in for the
///   queue policy that lets `sns.amazonaws.com` send on SQS; setting it
///   needs `sqs:TagQueue`.
/// - `kythira:sns-bridge-raw`: `true` for raw delivery.
///
/// Answers: 200 when handled (SNS stops retrying), 4xx for a request that
/// will never be taken (unknown queue, topic not allowed, bad signature),
/// 5xx when a retry may work (the certificate or the subscribe URL could
/// not be fetched, the send did not commit). Standard queues only: SNS
/// delivers to HTTPS only from standard topics.
///
/// A replayed request is taken again (a signature does not expire); a
/// standard queue delivers at least once, so consumers already handle a
/// duplicate.
///
/// Kythira's own SNS delivers to Kythira SQS directly, not through this
/// bridge (Requirement 10.2).

#include <kythira/sqs/sqs_front_end.hpp>

#include <raft/aws_json_protocol.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <boost/json.hpp>

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

struct sns_bridge_config {
    std::string _region = "us-east-1";
    std::string _partition = "aws";
    /// Where queue URLs point (`SQS_ENDPOINT`).
    std::string _endpoint;
    /// Hosts the signing certificate and the subscribe URL may come from.
    /// Empty: `sns.<region>.amazonaws.com`.
    std::vector<std::string> _hosts;
    /// One HTTPS GET: the body on a 2xx answer, else nullopt.
    std::function<std::optional<std::string>(const std::string& url)> _fetch;
};

struct sns_bridge_response {
    unsigned _status = 200;
    std::string _body;
};

namespace sns_detail {

/// "https://host/path" split, or nullopt for anything else (no port, no
/// user info: SNS's URLs have neither).
struct https_url {
    std::string _host;
    std::string _path;
};

[[nodiscard]] inline auto parse_https(std::string_view url) -> std::optional<https_url> {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme)) {
        return std::nullopt;
    }
    url.remove_prefix(scheme.size());
    const auto slash = url.find('/');
    const auto host = url.substr(0, slash);
    if (host.empty() || host.find_first_of(":@") != std::string_view::npos) {
        return std::nullopt;
    }
    return https_url{std::string(host),
                     slash == std::string_view::npos ? "/" : std::string(url.substr(slash))};
}

[[nodiscard]] inline auto str(const boost::json::object& o, std::string_view k)
    -> std::optional<std::string> {
    const auto* v = o.if_contains(k);
    if (v == nullptr || !v->is_string()) {
        return std::nullopt;
    }
    return std::string(v->get_string());
}

/// The string SNS signs for a message of type `type`
/// (docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html),
/// or nullopt when a field it needs is missing.
[[nodiscard]] inline auto string_to_sign(const boost::json::object& m)
    -> std::optional<std::string> {
    const auto type = str(m, "Type").value_or("");
    std::vector<std::string_view> fields;
    if (type == "Notification") {
        fields = {"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"};
    } else if (type == "SubscriptionConfirmation" || type == "UnsubscribeConfirmation") {
        fields = {"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"};
    } else {
        return std::nullopt;
    }
    std::string out;
    for (const auto f : fields) {
        const auto v = str(m, f);
        if (!v) {
            if (f == "Subject") {
                continue;  // optional, and left out of the string when absent
            }
            return std::nullopt;
        }
        out.append(f).append("\n").append(*v).append("\n");
    }
    return out;
}

struct bio_deleter {
    void operator()(BIO* b) const { BIO_free(b); }
};
struct x509_deleter {
    void operator()(X509* x) const { X509_free(x); }
};
struct pkey_deleter {
    void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
};
struct md_ctx_deleter {
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

/// Whether `signature_b64` is `pem`'s key's signature over `text` with
/// SHA1 (version "1") or SHA256 (version "2"), from a certificate valid
/// now.
[[nodiscard]] inline auto verify(const std::string& pem, std::string_view version,
                                 std::string_view text, std::string_view signature_b64) -> bool {
    const EVP_MD* md = version == "1" ? EVP_sha1() : version == "2" ? EVP_sha256() : nullptr;
    const auto sig = aws_json::base64_decode(signature_b64);
    if (md == nullptr || !sig || sig->empty()) {
        return false;
    }
    const std::unique_ptr<BIO, bio_deleter> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    const std::unique_ptr<X509, x509_deleter> cert(
        bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    if (!cert || X509_cmp_current_time(X509_get0_notBefore(cert.get())) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert.get())) < 0) {
        return false;
    }
    const std::unique_ptr<EVP_PKEY, pkey_deleter> key(X509_get_pubkey(cert.get()));
    const std::unique_ptr<EVP_MD_CTX, md_ctx_deleter> ctx(EVP_MD_CTX_new());
    return key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key.get()) == 1 &&
           EVP_DigestVerifyUpdate(ctx.get(), text.data(), text.size()) == 1 &&
           EVP_DigestVerifyFinal(ctx.get(),
                                 reinterpret_cast<const unsigned char*>(sig->data()),  // NOLINT
                                 sig->size()) == 1;
}

/// SNS message attributes (`{"name": {"Type": ..., "Value": ...}}`) as
/// SendMessage's (`{"name": {"DataType": ..., "StringValue"|"BinaryValue":
/// ...}}`).
[[nodiscard]] inline auto sqs_attributes(const boost::json::object& m) -> boost::json::object {
    boost::json::object out;
    const auto* a = m.if_contains("MessageAttributes");
    if (a == nullptr || !a->is_object()) {
        return out;
    }
    for (const auto& kv : a->get_object()) {
        if (!kv.value().is_object()) {
            continue;
        }
        const auto& v = kv.value().get_object();
        const auto type = str(v, "Type").value_or("String");
        const auto value = str(v, "Value").value_or("");
        boost::json::object e{{"DataType", type}};
        e[type.starts_with("Binary") ? "BinaryValue" : "StringValue"] = value;
        out[kv.key()] = std::move(e);
    }
    return out;
}

/// The body SNS's SQS delivery writes when raw delivery is off.
[[nodiscard]] inline auto envelope(const boost::json::object& m) -> std::string {
    boost::json::object out;
    for (const auto* k :
         {"Type", "MessageId", "TopicArn", "Subject", "Message", "Timestamp", "SignatureVersion",
          "Signature", "SigningCertURL", "UnsubscribeURL", "MessageAttributes"}) {
        if (const auto* v = m.if_contains(k)) {
            out[k] = *v;
        }
    }
    return boost::json::serialize(out);
}

[[nodiscard]] inline auto tag_lists(std::string_view list, std::string_view item) -> bool {
    while (!list.empty()) {
        const auto comma = list.find(',');
        auto one = list.substr(0, comma);
        while (!one.empty() && one.front() == ' ') {
            one.remove_prefix(1);
        }
        while (!one.empty() && one.back() == ' ') {
            one.remove_suffix(1);
        }
        if (one == item) {
            return true;
        }
        list = comma == std::string_view::npos ? std::string_view() : list.substr(comma + 1);
    }
    return false;
}

}  // namespace sns_detail

/// The bridge. `Service` is `sqs_service<Cluster>`.
template<typename Service> class sns_bridge {
public:
    static constexpr std::string_view k_prefix = "/sns-bridge/";
    static constexpr std::string_view k_topics_tag = "kythira:sns-bridge-topics";
    static constexpr std::string_view k_raw_tag = "kythira:sns-bridge-raw";

    /// @param service Outlives the bridge.
    sns_bridge(Service& service, sns_bridge_config config)
        : _service(service), _config(std::move(config)) {
        if (_config._hosts.empty()) {
            _config._hosts.push_back("sns." + _config._region + ".amazonaws.com");
        }
    }

    /// One request to `k_prefix<account>/<queue>`.
    auto handle(std::string_view method, std::string_view path, std::string_view body)
        -> sns_bridge_response {
        using namespace sns_detail;
        if (method != "POST") {
            return {405, "POST only\n"};
        }
        auto rest = path.substr(std::min(path.size(), k_prefix.size()));
        const auto slash = rest.find('/');
        if (!path.starts_with(k_prefix) || slash == std::string_view::npos || slash == 0 ||
            slash + 1 == rest.size()) {
            return {404, "no such queue\n"};
        }
        const std::string account(rest.substr(0, slash));
        const std::string name(rest.substr(slash + 1));
        boost::system::error_code ec;
        auto parsed = boost::json::parse(body, ec);
        if (ec || !parsed.is_object()) {
            return {400, "not an SNS message\n"};
        }
        const auto& m = parsed.get_object();
        const auto type = str(m, "Type").value_or("");
        const auto topic = str(m, "TopicArn").value_or("");

        const auto q = _service.find(account, name);
        if (!q) {
            return {404, "no such queue\n"};
        }
        const auto allowed = q->_tags.find(std::string(k_topics_tag));
        if (allowed == q->_tags.end() ||
            !(tag_lists(allowed->second, topic) ||
              (allowed->second == "*" && topic_account(topic) == account))) {
            return {403, "this queue does not take deliveries from that topic\n"};
        }
        if (q->_settings._fifo) {
            return {400, "SNS delivers to HTTPS only from standard topics\n"};
        }

        // The signature, from a certificate on an allowed host.
        const auto text = string_to_sign(m);
        const auto cert_url = str(m, "SigningCertURL").value_or("");
        const auto cert = parse_https(cert_url);
        if (!text || !cert || !allowed_host(cert->_host) || !cert->_path.ends_with(".pem")) {
            return {403, "unsigned, or signed by a certificate from a host not allowed\n"};
        }
        const auto pem = certificate(cert_url);
        if (!pem) {
            return {503, "the signing certificate could not be fetched\n"};
        }
        if (!verify(*pem, str(m, "SignatureVersion").value_or(""), *text,
                    str(m, "Signature").value_or(""))) {
            return {403, "bad signature\n"};
        }

        if (type == "SubscriptionConfirmation") {
            const auto url = str(m, "SubscribeURL").value_or("");
            const auto u = parse_https(url);
            if (!u || !allowed_host(u->_host)) {
                return {403, "subscribe URL on a host not allowed\n"};
            }
            if (!_config._fetch || !_config._fetch(url)) {
                return {502, "the subscription could not be confirmed\n"};
            }
            return {200, "confirmed\n"};
        }
        if (type == "UnsubscribeConfirmation") {
            return {200, "\n"};
        }
        return enqueue(*q, account, name, m);
    }

    /// Notifications enqueued, for metrics.
    [[nodiscard]] auto delivered() const -> std::uint64_t {
        const std::scoped_lock lock(_mutex);
        return _delivered;
    }

private:
    static constexpr std::size_t k_max_certificates = 64;

    Service& _service;
    sns_bridge_config _config;
    mutable std::mutex _mutex;
    std::map<std::string, std::string> _certificates;  // by URL
    std::uint64_t _delivered = 0;

    [[nodiscard]] static auto topic_account(std::string_view arn) -> std::string_view {
        // arn:<partition>:sns:<region>:<account>:<topic>
        for (int i = 0; i < 4; ++i) {
            const auto colon = arn.find(':');
            if (colon == std::string_view::npos) {
                return {};
            }
            arn.remove_prefix(colon + 1);
        }
        return arn.substr(0, arn.find(':'));
    }

    [[nodiscard]] auto allowed_host(std::string_view host) const -> bool {
        for (const auto& h : _config._hosts) {
            if (h == host) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto certificate(const std::string& url) -> std::optional<std::string> {
        {
            const std::scoped_lock lock(_mutex);
            if (const auto it = _certificates.find(url); it != _certificates.end()) {
                return it->second;
            }
        }
        auto pem = _config._fetch ? _config._fetch(url) : std::nullopt;
        if (!pem) {
            return std::nullopt;
        }
        const std::scoped_lock lock(_mutex);
        if (_certificates.size() >= k_max_certificates) {
            _certificates.clear();
        }
        _certificates[url] = *pem;
        return pem;
    }

    auto enqueue(const queue_record& q, const std::string& account, const std::string& name,
                 const boost::json::object& m) -> sns_bridge_response {
        const auto raw = q._tags.find(std::string(k_raw_tag));
        const bool is_raw = raw != q._tags.end() && raw->second == "true";
        boost::json::object in;
        if (is_raw) {
            in["MessageBody"] = sns_detail::str(m, "Message").value_or("");
            if (auto attrs = sns_detail::sqs_attributes(m); !attrs.empty()) {
                in["MessageAttributes"] = std::move(attrs);
            }
        } else {
            in["MessageBody"] = sns_detail::envelope(m);
        }
        sqs_call_context ctx;
        ctx._operation = "SendMessage";
        ctx._request_id = sns_detail::str(m, "MessageId").value_or("");
        ctx._region = _config._region;
        ctx._partition = _config._partition;
        ctx._endpoint = _config._endpoint;
        ctx._principal.account = account;
        ctx._principal.userid = "sns.amazonaws.com";
        ctx._queue = ctx.make_queue_ref(account, name);
        // The queue's tag authorized the delivery.
        ctx._authorize = [](const aws_auth::authz_request&) {
            return std::optional<aws_json::error>{};
        };
        ctx._authorized = true;
        try {
            const auto out = _service.deliver(ctx, in);
            if (!out) {
                // A message SQS refuses (too large, bad characters) never
                // will be taken: tell SNS to stop.
                const auto st = out.error().status;
                return {st >= 500 ? 500U : 400U, out.error().message.value_or("refused") + "\n"};
            }
        } catch (const std::exception&) {
            return {500, "not committed\n"};
        }
        const std::scoped_lock lock(_mutex);
        ++_delivered;
        return {200, "\n"};
    }
};

}  // namespace kythira::sqs
