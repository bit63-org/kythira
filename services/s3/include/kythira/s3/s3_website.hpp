// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_website.hpp
/// @brief `PutBucketWebsite`, `GetBucketWebsite`, `DeleteBucketWebsite`
///        and the website endpoint
///        (.kiro/specs/s3-compatible-storage/ task 15, Requirement 12.4).
///
/// The website endpoint answers a `GET` or `HEAD` sent to
/// `<bucket>.<website domain>` (`service_options::website_domains`) as
/// S3's `s3-website` endpoints do:
///
/// - Requests are never authenticated: every read is checked as the
///   anonymous principal (`s3:GetObject` on the key), so a bucket serves
///   only what its policy or ACLs make public.
/// - `RedirectAllRequestsTo` answers `301` to the same path on the other
///   host.
/// - Otherwise the first routing rule without an error-code condition
///   that matches the key redirects before anything is read.
/// - A key that is empty or ends in `/` gets the index suffix. A missing
///   key `k` whose `k/<suffix>` exists answers `302` to `/k/`.
/// - An object with `x-amz-website-redirect-location` answers `301` there.
/// - Any other object is served as `GetObject` serves it (ranges and
///   conditions included).
/// - A missing key is `404 NoSuchKey` when the anonymous principal may
///   list the bucket, else `403 AccessDenied`, as on S3.
/// - An error first tries the routing rules with its HTTP code, then the
///   error document (served with the error's status), then S3's HTML
///   error page, which also says why the error document could not be
///   served.

#include <kythira/s3/s3_auth.hpp>
#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_object_lock.hpp>
#include <kythira/s3/s3_objects.hpp>
#include <kythira/s3/s3_website_rules.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// The sub-resource
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_website(handler_context<M>& ctx, const s3_request& req,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!lock_detail::has_integrity_header(req.headers)) {
        return website_detail::invalid_request(
            "Missing required header for this request: Content-MD5");
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto c = parse_website_configuration(*body);
    if (!c) {
        return c.error();
    }
    if (auto e = bucket_detail::store(ctx, b, "website", website_xml(*c))) {
        return *e;
    }
    return s3_response{};
}

namespace website_detail {

[[nodiscard]] inline auto no_such_website(std::string_view bucket) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(404, "NoSuchWebsiteConfiguration",
                                        "The specified bucket does not have a website "
                                        "configuration");
    e.extra.emplace_back("BucketName", std::string(bucket));
    return e;
}

}  // namespace website_detail

template<metadata_access M>
[[nodiscard]] auto get_bucket_website(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.website) {
        return website_detail::no_such_website(b.client_name);
    }
    return xml_response(website_xml(*b.website));
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_website(handler_context<M>& ctx, const s3_request& /*req*/,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "website", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

// ---------------------------------------------------------------------------
// The website endpoint
// ---------------------------------------------------------------------------

/// The bucket and key a website request names: the `Host` must be
/// `<bucket>.<domain>` for a website domain (website endpoints have no
/// path style). None when the host is not a website host.
[[nodiscard]] inline auto website_resource(std::string_view host, std::string_view target,
                                           const std::vector<std::string>& domains)
    -> std::optional<aws_rest_xml::result<aws_rest_xml::resource>> {
    if (domains.empty()) {
        return std::nullopt;
    }
    const auto path = target.substr(0, target.find('?'));
    auto r = aws_rest_xml::parse_resource(host, path.empty() ? "/" : path,
                                          aws_rest_xml::addressing_config{domains});
    if (r && r->style != aws_rest_xml::addressing_style::virtual_hosted) {
        return std::nullopt;
    }
    return r;
}

/// The HTML answer for `e` (no body for HEAD).
[[nodiscard]] inline auto website_error_response(
    const aws_rest_xml::error& e, std::string_view request_id, bool head,
    const std::optional<aws_rest_xml::error>& document_error = std::nullopt) -> s3_response {
    s3_response r;
    r.status = e.status;
    if (!head) {
        r.body = website_error_html(e, request_id, document_error);
        r.set("Content-Type", "text/html; charset=utf-8");
    }
    return r;
}

[[nodiscard]] inline auto website_redirect_response(unsigned status, std::string location)
    -> s3_response {
    s3_response r;
    r.status = status;
    r.set("Location", std::move(location));
    return r;
}

namespace website_detail {

/// An error answer from a handler (an `<Error>` document, or no body for
/// HEAD) back as the error it was.
[[nodiscard]] inline auto error_of(const s3_response& r) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(r.status, "", "");
    if (auto doc = aws_rest_xml::parse_xml(r.body)) {
        e.code = doc->child_text("Code").value_or("");
        e.message = doc->child_text("Message").value_or("");
        for (const auto& c : doc->children) {
            if (c.name != "Code" && c.name != "Message" && c.name != "RequestId" &&
                c.name != "HostId") {
                e.extra.emplace_back(c.name, c.text);
            }
        }
    }
    return e;
}

}  // namespace website_detail

/// Serve one website request for bucket `b`. `req` carries the method,
/// headers, request id and the decoded key; `host` is the request's
/// `Host`. `allowed(operation, key)` runs the anonymous access check
/// (`GetObject` on a key, `ListObjectsV2` on the bucket).
template<metadata_access M, typename Allowed>
[[nodiscard]] auto serve_website(handler_context<M>& ctx, bucket_state& b, const s3_request& req,
                                 std::string_view host, const Allowed& allowed) -> s3_response {
    const bool head = req.method == "HEAD";
    const auto& id = req.request_id;
    if (req.method != "GET" && req.method != "HEAD") {
        auto e = aws_rest_xml::errors::method_not_allowed();
        e.extra.emplace_back("Method", req.method);
        e.extra.emplace_back("ResourceType", "OBJECT");
        return website_error_response(e, id, head);
    }
    if (!b.website) {
        return website_error_response(website_detail::no_such_website(b.client_name), id, head);
    }
    const auto& w = *b.website;
    const std::string protocol = req.secure_transport ? "https" : "http";
    const auto& key = req.resource.key;
    if (w.redirect_all) {
        const auto& to = *w.redirect_all;
        return website_redirect_response(301, (to.protocol.empty() ? protocol : to.protocol) +
                                                  "://" + to.host_name + website_path(key));
    }
    if (const auto* rule = match_routing_rule(w, key, std::nullopt)) {
        return website_redirect_response(rule->redirect.http_redirect_code.value_or(301),
                                         routing_location(*rule, key, host, protocol));
    }

    const authenticated anonymous;
    const auto exists = [&](const std::string& k) {
        auto v = ctx.meta.version(b.desc.id, k, std::nullopt);
        return v && !v->delete_marker;
    };
    // An object's answer, or the error that stands in for it.
    using fetched = std::variant<s3_response, aws_rest_xml::error>;
    const auto fetch = [&](const std::string& k, bool follow_redirect) -> fetched {
        if (!allowed(std::string_view("GetObject"), k)) {
            return access_denied();
        }
        auto v = ctx.meta.version(b.desc.id, k, std::nullopt);
        if (!v || v->delete_marker) {
            if (!allowed(std::string_view("ListObjectsV2"), std::string{})) {
                return access_denied();
            }
            return object_detail::no_such_key(k);
        }
        if (follow_redirect) {
            const auto& meta = v->content.system_metadata;
            if (auto it = meta.find("x-amz-website-redirect-location"); it != meta.end()) {
                return website_redirect_response(301, it->second);
            }
        }
        s3_request get;
        get.method = req.method;
        get.resource = req.resource;
        get.resource.key = k;
        for (const auto& [name, value] : req.headers) {
            // The error document is served whole and unconditionally.
            const auto n = cors_detail::lower(name);
            if (follow_redirect || (n != "range" && !n.starts_with("if-"))) {
                get.headers.emplace_back(name, value);
            }
        }
        get.source_ip = req.source_ip;
        get.secure_transport = req.secure_transport;
        get.request_id = id;
        auto r = get_object(ctx, get, anonymous, b);
        if (!r) {
            return r.error();
        }
        if (r->status >= 400) {
            return website_detail::error_of(*r);
        }
        return std::move(*r);
    };

    std::string object_key = key;
    if (key.empty() || key.ends_with('/')) {
        object_key += w.index_suffix;
    }
    auto got = fetch(object_key, true);
    if (auto* r = std::get_if<s3_response>(&got)) {
        return std::move(*r);
    }
    auto error = std::get<aws_rest_xml::error>(std::move(got));
    // A missing key, whether or not the anonymous principal may list (and
    // so learn of it as 404 or 403), whose folder index is readable.
    if (object_key == key && (error.status == 404 || error.status == 403) && !exists(key) &&
        allowed(std::string_view("GetObject"), key + "/" + w.index_suffix) &&
        exists(key + "/" + w.index_suffix)) {
        // A "folder" without its slash goes to the folder's index.
        return website_redirect_response(302, website_path(key) + "/");
    }
    if (const auto* rule = match_routing_rule(w, key, error.status)) {
        return website_redirect_response(rule->redirect.http_redirect_code.value_or(301),
                                         routing_location(*rule, key, host, protocol));
    }
    if (w.error_document && error.status >= 400 && error.status < 500) {
        auto doc = fetch(*w.error_document, false);
        if (auto* r = std::get_if<s3_response>(&doc)) {
            if (r->status == 200) {
                r->status = error.status;
            }
            return std::move(*r);
        }
        return website_error_response(error, id, head, std::get<aws_rest_xml::error>(doc));
    }
    return website_error_response(error, id, head);
}

}  // namespace kythira::s3
