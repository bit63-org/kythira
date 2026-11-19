// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_service.hpp
/// @brief The S3 request pipeline: route, authenticate, check the body,
///        authorize, handle (.kiro/specs/s3-compatible-storage/ tasks 6
///        and 7).
///
/// `s3_service::serve` takes a request as the listener parsed it (method,
/// `Host`, target, headers, a pull source for the raw body) and returns the
/// response. In order:
///
/// 1. **Route** by the pinned model (`s3_routes.hpp`). A browser POST
///    (`POST /bucket` with `multipart/form-data`) is not a model
///    operation and goes to the POST upload path instead.
/// 2. **Authenticate** (`s3_auth.hpp`): SigV4 header or query, or
///    anonymous. The raw body is wrapped in a `payload_reader`, so
///    handlers only ever see bytes the signature vouches for, and a bad
///    chunk signature or body hash fails the request before any manifest
///    is committed.
/// 3. **Find the bucket** (unless the operation is service-level). A
///    missing bucket is `NoSuchBucket` for anyone, as on S3.
/// 4. **Authorize** every check the request needs (`s3_authz.hpp`) with
///    the bucket's policy, ownership, ACLs and Block Public Access
///    (`s3_access.hpp`); a copy's source is checked against its own
///    bucket. DeleteObjects authorizes each key as it goes.
/// 5. **Handle** (`s3_buckets.hpp`, `s3_objects.hpp`, `s3_listings.hpp`,
///    `s3_multipart.hpp`, `s3_versioning.hpp`).
///    Operations not built yet answer `501 NotImplemented`
///    (`doc/unsupported.md`).
///
/// Every response carries `x-amz-request-id` and `x-amz-id-2`; every
/// error is S3's XML `<Error>` (none for HEAD).

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_auth.hpp>
#include <kythira/s3/s3_authz.hpp>
#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_lifecycle.hpp>
#include <kythira/s3/s3_listings.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_multipart.hpp>
#include <kythira/s3/s3_notifications.hpp>
#include <kythira/s3/s3_objects.hpp>
#include <kythira/s3/s3_post_policy.hpp>
#include <kythira/s3/s3_replication.hpp>
#include <kythira/s3/s3_routes.hpp>
#include <kythira/s3/s3_versioning.hpp>

#include <raft/aws_request_authorizer.hpp>
#include <raft/aws_rest_xml_protocol.hpp>
#include <raft/sigv4_verifier.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// A request as the listener parsed it.
struct http_request {
    std::string method;
    std::string host;
    std::string target;  ///< path and query, as sent
    header_list headers;
    body_source body;
    std::string source_ip;
    bool secure_transport = true;
};

/// The operations `serve` implements (`implemented-operations.txt`).
[[nodiscard]] inline auto implemented_operations() -> const std::set<std::string, std::less<>>& {
    static const std::set<std::string, std::less<>> ops{
        // Service and bucket.
        "CreateBucket", "DeleteBucket", "HeadBucket", "ListBuckets", "GetBucketLocation",
        "GetBucketLogging", "PutBucketLogging", "GetBucketRequestPayment", "GetBucketTagging",
        "PutBucketTagging", "DeleteBucketTagging", "GetBucketPolicy", "PutBucketPolicy",
        "DeleteBucketPolicy", "GetBucketPolicyStatus", "GetBucketAcl", "PutBucketAcl",
        "GetBucketOwnershipControls", "PutBucketOwnershipControls", "DeleteBucketOwnershipControls",
        "GetPublicAccessBlock", "PutPublicAccessBlock", "DeletePublicAccessBlock",
        "GetBucketEncryption", "PutBucketEncryption", "DeleteBucketEncryption",
        // Objects.
        "PutObject", "GetObject", "HeadObject", "DeleteObject", "DeleteObjects", "CopyObject",
        "GetObjectAttributes", "GetObjectTagging", "PutObjectTagging", "DeleteObjectTagging",
        "GetObjectAcl", "PutObjectAcl", "ListObjects", "ListObjectsV2",
        // Multipart upload.
        "CreateMultipartUpload", "UploadPart", "UploadPartCopy", "ListParts",
        "ListMultipartUploads", "CompleteMultipartUpload", "AbortMultipartUpload",
        // Versioning and object lock.
        "GetBucketVersioning", "PutBucketVersioning", "ListObjectVersions",
        "GetObjectLockConfiguration", "PutObjectLockConfiguration", "GetObjectRetention",
        "PutObjectRetention", "GetObjectLegalHold", "PutObjectLegalHold",
        // Lifecycle and restores.
        "GetBucketLifecycle", "GetBucketLifecycleConfiguration", "PutBucketLifecycle",
        "PutBucketLifecycleConfiguration", "DeleteBucketLifecycle", "RestoreObject",
        // Event notifications.
        "GetBucketNotification", "GetBucketNotificationConfiguration", "PutBucketNotification",
        "PutBucketNotificationConfiguration",
        // Replication.
        "GetBucketReplication", "PutBucketReplication", "DeleteBucketReplication"};
    return ops;
}

template<metadata_access M, aws_auth::aws_request_authorizer A> class s3_service {
public:
    s3_service(M& meta, data_path& data, A& authorizer, service_options options)
        : _options(std::move(options)),
          _authorizer(&authorizer),
          _ctx{meta, data, _options},
          _rates(_options.rates, _options.on_hot_prefix),
          _rules(s3_rules({_options.region})) {}

    s3_service(const s3_service&) = delete;
    auto operator=(const s3_service&) -> s3_service& = delete;
    s3_service(s3_service&&) = delete;
    auto operator=(s3_service&&) -> s3_service& = delete;
    ~s3_service() = default;

    [[nodiscard]] auto options() const -> const service_options& { return _options; }
    [[nodiscard]] auto rates() const -> const prefix_rates& { return _rates; }

    auto serve(http_request in) -> s3_response {
        const auto request_id = new_request_id();
        auto out = serve_inner(in, request_id);
        out.set("x-amz-request-id", request_id);
        out.set("x-amz-id-2", request_id);
        return out;
    }

private:
    using handler_fn = handler_result (*)(handler_context<M>&, const s3_request&,
                                          const authenticated&, bucket_state&);

    [[nodiscard]] static auto bucket_handler(std::string_view op) -> handler_fn {
        static const std::vector<std::pair<std::string_view, handler_fn>> table{
            {"DeleteBucket", &delete_bucket<M>},
            {"HeadBucket", &head_bucket<M>},
            {"GetBucketLocation", &get_bucket_location<M>},
            {"GetBucketLogging", &get_bucket_logging<M>},
            {"PutBucketLogging", &put_bucket_logging<M>},
            {"GetBucketRequestPayment", &get_bucket_request_payment<M>},
            {"GetBucketTagging", &get_bucket_tagging<M>},
            {"PutBucketTagging", &put_bucket_tagging<M>},
            {"DeleteBucketTagging", &delete_bucket_tagging<M>},
            {"GetBucketEncryption", &get_bucket_encryption<M>},
            {"PutBucketEncryption", &put_bucket_encryption<M>},
            {"DeleteBucketEncryption", &delete_bucket_encryption<M>},
            {"GetBucketLifecycleConfiguration", &get_bucket_lifecycle<M>},
            {"GetBucketLifecycle", &get_bucket_lifecycle<M>},
            {"PutBucketLifecycleConfiguration", &put_bucket_lifecycle<M>},
            {"PutBucketLifecycle", &put_bucket_lifecycle<M>},
            {"DeleteBucketLifecycle", &delete_bucket_lifecycle<M>},
            {"GetBucketNotification", &get_bucket_notification<M>},
            {"GetBucketNotificationConfiguration", &get_bucket_notification_configuration<M>},
            {"PutBucketNotification", &put_bucket_notification<M>},
            {"PutBucketNotificationConfiguration", &put_bucket_notification_configuration<M>},
            {"GetBucketReplication", &get_bucket_replication<M>},
            {"PutBucketReplication", &put_bucket_replication<M>},
            {"DeleteBucketReplication", &delete_bucket_replication<M>},
            {"RestoreObject", &restore_object<M>},
            {"GetBucketPolicy", &get_bucket_policy<M>},
            {"PutBucketPolicy", &put_bucket_policy<M>},
            {"DeleteBucketPolicy", &delete_bucket_policy<M>},
            {"GetBucketPolicyStatus", &get_bucket_policy_status<M>},
            {"GetBucketAcl", &get_bucket_acl<M>},
            {"PutBucketAcl", &put_bucket_acl<M>},
            {"GetBucketOwnershipControls", &get_bucket_ownership_controls<M>},
            {"PutBucketOwnershipControls", &put_bucket_ownership_controls<M>},
            {"DeleteBucketOwnershipControls", &delete_bucket_ownership_controls<M>},
            {"GetPublicAccessBlock", &get_public_access_block<M>},
            {"PutPublicAccessBlock", &put_public_access_block<M>},
            {"CreateMultipartUpload", &create_multipart_upload<M>},
            {"UploadPart", &upload_part<M>},
            {"ListParts", &list_parts<M>},
            {"ListMultipartUploads", &list_multipart_uploads<M>},
            {"CompleteMultipartUpload", &complete_multipart_upload<M>},
            {"AbortMultipartUpload", &abort_multipart_upload<M>},
            {"GetBucketVersioning", &get_bucket_versioning<M>},
            {"PutBucketVersioning", &put_bucket_versioning<M>},
            {"ListObjectVersions", &list_object_versions<M>},
            {"GetObjectLockConfiguration", &get_object_lock_configuration<M>},
            {"PutObjectLockConfiguration", &put_object_lock_configuration<M>},
            {"GetObjectRetention", &get_object_retention<M>},
            {"PutObjectRetention", &put_object_retention<M>},
            {"GetObjectLegalHold", &get_object_legal_hold<M>},
            {"PutObjectLegalHold", &put_object_legal_hold<M>},
            {"DeletePublicAccessBlock", &delete_public_access_block<M>},
            {"PutObject", &put_object<M>},
            {"GetObject", &get_object<M>},
            {"HeadObject", &get_object<M>},
            {"DeleteObject", &delete_object<M>},
            {"GetObjectAttributes", &get_object_attributes<M>},
            {"GetObjectTagging", &get_object_tagging<M>},
            {"PutObjectTagging", &put_object_tagging<M>},
            {"DeleteObjectTagging", &delete_object_tagging<M>},
            {"GetObjectAcl", &get_object_acl<M>},
            {"PutObjectAcl", &put_object_acl<M>},
            {"ListObjects", &list_objects<M>},
            {"ListObjectsV2", &list_objects_v2<M>},
        };
        for (const auto& [name, fn] : table) {
            if (name == op) {
                return fn;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto now_seconds() const -> std::chrono::sys_seconds {
        return std::chrono::floor<std::chrono::seconds>(_ctx.now());
    }

    auto serve_inner(http_request& in, const std::string& request_id) -> s3_response {
        const bool head = in.method == "HEAD";
        const auto fail = [&](const aws_rest_xml::error& e) {
            return error_response(e, request_id, head);
        };
        const auto content_type = find_header(in.headers, "Content-Type").value_or("");
        if (in.method == "POST" && in.target.find('?') == std::string::npos &&
            form_boundary(content_type)) {
            return post_upload(in, request_id);
        }

        const auto has_header = [&](std::string_view name) {
            return find_header(in.headers, name).has_value();
        };
        auto routed = route_request(in.method, in.host, in.target, _options.addressing, has_header);
        if (!routed) {
            return fail(routed.error());
        }
        const auto qmark = in.target.find('?');
        const std::string_view path = std::string_view(in.target).substr(0, qmark);
        const std::string_view raw_query = qmark == std::string::npos
                                               ? std::string_view{}
                                               : std::string_view(in.target).substr(qmark + 1);
        const sigv4::request signed_view{in.method, path, raw_query, in.headers, std::nullopt};
        auto auth = authenticate(*_authorizer, signed_view, _rules, now_seconds());
        if (!auth) {
            return fail(auth.error());
        }

        s3_request req;
        req.method = in.method;
        req.operation = routed->operation;
        req.resource = std::move(routed->resource);
        req.query = std::move(routed->query);
        req.headers = in.headers;
        req.source_ip = in.source_ip;
        req.secure_transport = in.secure_transport;
        req.request_id = request_id;
        auto reader = std::make_shared<payload_reader>(*auth, signed_view);
        req.trailers = [reader] { return reader->trailers(); };
        req.body = checked_body(reader, std::move(in.body));

        const std::string op(req.op());
        if (!implemented_operations().contains(op)) {
            return fail(not_implemented());
        }
        auto result = dispatch(op, req, *auth);
        if (!result) {
            return fail(result.error());
        }
        return std::move(*result);
    }

    /// The raw body through the payload reader.
    [[nodiscard]] static auto checked_body(std::shared_ptr<payload_reader> reader, body_source raw)
        -> body_source {
        auto done = std::make_shared<bool>(false);
        return
            [reader, done, raw = std::move(raw)](std::string& out) -> aws_rest_xml::result<bool> {
                if (*done) {
                    return false;
                }
                std::string chunk;
                bool more = false;
                if (raw) {
                    auto r = raw(chunk);
                    if (!r) {
                        return r.error();
                    }
                    more = *r;
                }
                if (auto e = reader->feed(chunk, out)) {
                    return *e;
                }
                if (!more) {
                    *done = true;
                    if (auto e = reader->finish()) {
                        return *e;
                    }
                }
                return more;
            };
    }

    // ---- authorization ------------------------------------------------------

    [[nodiscard]] auto facts_for(const s3_request& req, const authenticated& auth,
                                 const bucket_state* b) const -> request_facts {
        request_facts f;
        f.operation = std::string(req.op());
        f.bucket = req.resource.bucket;
        f.key = req.resource.key;
        f.headers = req.headers;
        f.query = req.query;
        f.version_id = req.query.get("versionId");
        f.auth_type = auth.auth_type();
        f.signature_age_ms = auth.signature_age_ms;
        f.partition = _options.partition;
        if (b != nullptr) {
            f.resource_account = b->desc.owner;
            f.bucket_tags = b->tags;
        }
        return f;
    }

    /// The object's ACL and tags, when a check may need them.
    struct object_facts {
        std::optional<access_control_list> acl;
        std::vector<std::pair<std::string, std::string>> tags;
    };

    [[nodiscard]] auto load_object(const bucket_state& b, const std::string& key,
                                   const std::optional<std::string>& version) const
        -> object_facts {
        object_facts out;
        if (key.empty()) {
            return out;
        }
        if (version && !object_detail::valid_version_id(*version)) {
            return out;
        }
        auto v = _ctx.meta.version(b.desc.id, key, version);
        if (!v || v->delete_marker) {
            return out;
        }
        out.tags = object_detail::stored_tags(*v);
        if (b.ownership != object_ownership::bucket_owner_enforced) {
            out.acl = object_detail::acl_of(*v);
        }
        return out;
    }

    [[nodiscard]] auto authorize(const request_facts& facts, const authenticated& auth,
                                 bucket_state& b, const bucket_state* source,
                                 const object_facts& target_object,
                                 const object_facts& source_object)
        -> std::optional<aws_rest_xml::error> {
        const auto checks = checks_for(facts);
        access_context target_ctx = b.access;
        target_ctx.object_acl = target_object.acl ? &*target_object.acl : nullptr;
        access_context source_ctx;
        if (source != nullptr) {
            source_ctx = source->access;
            source_ctx.object_acl = source_object.acl ? &*source_object.acl : nullptr;
        }
        const auto source_arn =
            source != nullptr ? bucket_arn(_options.partition, facts.source_bucket) : std::string{};
        const auto target_arn = bucket_arn(_options.partition, facts.bucket);
        const auto names = [](const std::string& resource, const std::string& arn) {
            return resource == arn || resource.starts_with(arn + "/");
        };
        return authorize_all(*_authorizer, auth, checks,
                             [&](const authz_check& c) -> const access_context* {
                                 if (source != nullptr && names(c.resource, source_arn) &&
                                     !names(c.resource, target_arn)) {
                                     return &source_ctx;
                                 }
                                 if (source != nullptr && names(c.resource, source_arn) &&
                                     c.action.starts_with("s3:GetObject")) {
                                     return &source_ctx;  // copy within one bucket
                                 }
                                 return &target_ctx;
                             });
    }

    // ---- dispatch -----------------------------------------------------------

    auto find_bucket(const std::string& name, const authenticated& auth, const s3_request& req,
                     bucket_state& out) -> std::optional<aws_rest_xml::error> {
        if (_options.account_namespaces && !auth.who) {
            return no_such_bucket(name);
        }
        auto desc = _ctx.meta.bucket(_ctx.catalog_name(name, auth.who ? auth.who->account : ""));
        if (!desc) {
            return no_such_bucket(name);
        }
        load_bucket_state(_ctx, std::move(*desc), out, req);
        return std::nullopt;
    }

    auto dispatch(const std::string& op, s3_request& req, const authenticated& auth)
        -> handler_result {
        if (op == "ListBuckets" || op == "CreateBucket") {
            if (!auth.who) {
                return access_denied();
            }
            auto facts = facts_for(req, auth, nullptr);
            if (op == "CreateBucket") {
                // The body names the location constraint, a condition key.
                auto body = bucket_detail::document(_ctx, req);
                if (!body) {
                    return body.error();
                }
                if (auto doc = aws_rest_xml::parse_xml(*body); doc && !body->empty()) {
                    facts.location_constraint = doc->child_text("LocationConstraint");
                }
                req.body = memory_body(std::move(*body));
                facts.resource_account = auth.who->account;
            }
            // Service-level checks name no bucket policy.
            access_context ctx;
            ctx.bucket_owner = auth.who->account;
            ctx.source_ip = req.source_ip;
            ctx.region = _options.region;
            ctx.secure_transport = req.secure_transport;
            if (auto e = authorize_all(*_authorizer, auth, checks_for(facts),
                                       [&](const authz_check&) { return &ctx; })) {
                return *e;
            }
            return op == "ListBuckets" ? list_buckets(_ctx, req, auth)
                                       : create_bucket(_ctx, req, auth);
        }

        bucket_state b;
        if (auto e = find_bucket(req.resource.bucket, auth, req, b)) {
            return *e;
        }
        if (auto e = admit(req, b)) {
            return *e;
        }
        auto facts = facts_for(req, auth, &b);

        if (op == "PutObjectTagging" || op == "PutBucketTagging") {
            auto body = bucket_detail::document(_ctx, req);
            if (!body) {
                return body.error();
            }
            if (auto tags = parse_tagging(*body)) {
                facts.request_tags = *tags;
            }
            req.body = memory_body(std::move(*body));
        }

        if (op == "DeleteObjects") {
            const auto may_delete = [&](const std::string& key,
                                        const std::optional<std::string>& version)
                -> std::optional<aws_rest_xml::error> {
                auto f = facts;
                f.key = key;
                f.version_id = version;
                const auto obj = load_object(b, key, version);
                f.existing_tags = obj.tags;
                return authorize(f, auth, b, nullptr, obj, {});
            };
            // The bucket-level part (none for DeleteObjects) is per key.
            return delete_objects(_ctx, req, auth, b, may_delete);
        }

        if (op == "CopyObject" || op == "UploadPartCopy") {
            const auto header = req.header("x-amz-copy-source").value_or("");
            auto src = parse_copy_source(header);
            if (!src) {
                return src.error();
            }
            bucket_state source;
            if (src->bucket == req.resource.bucket) {
                if (auto e = find_bucket(src->bucket, auth, req, source)) {
                    return *e;
                }
            } else if (auto e = find_bucket(src->bucket, auth, req, source)) {
                return *e;
            }
            facts.source_bucket = src->bucket;
            facts.source_key = src->key;
            facts.source_version_id = src->version_id;
            const auto target_obj = load_object(b, req.resource.key, std::nullopt);
            const auto source_obj = load_object(source, src->key, src->version_id);
            facts.existing_tags = source_obj.tags;
            if (auto e = authorize(facts, auth, b, &source, target_obj, source_obj)) {
                return *e;
            }
            if (op == "UploadPartCopy") {
                return upload_part_copy(_ctx, req, auth, b, source, *src);
            }
            return copy_object(_ctx, req, auth, b, source, *src);
        }

        const auto obj = load_object(b, req.resource.key, facts.version_id);
        facts.existing_tags = obj.tags;
        if (auto e = authorize(facts, auth, b, nullptr, obj, {})) {
            return *e;
        }
        const auto fn = bucket_handler(op);
        if (fn == nullptr) {
            return not_implemented();
        }
        return fn(_ctx, req, auth, b);
    }

    // ---- browser POST uploads ----------------------------------------------

    auto post_upload(http_request& in, const std::string& request_id) -> s3_response {
        const auto fail = [&](const aws_rest_xml::error& e) {
            return error_response(e, request_id);
        };
        auto resource = aws_rest_xml::parse_resource(in.host, in.target, _options.addressing);
        if (!resource) {
            return fail(resource.error());
        }
        if (!resource->key.empty()) {
            return fail(aws_rest_xml::errors::method_not_allowed());
        }
        const auto boundary =
            form_boundary(find_header(in.headers, "Content-Type").value_or("")).value_or("");
        form_reader form(boundary);
        std::string file;
        // Fields first: nothing of the file is stored before the form
        // authenticates and the access check passes.
        bool more = true;
        while (more && !form.fields_complete() && form.state() != form_reader::status::failed) {
            std::string raw;
            auto r = in.body ? in.body(raw) : aws_rest_xml::result<bool>(false);
            if (!r) {
                return fail(r.error());
            }
            more = *r;
            form.feed(raw, file);
        }
        if (!more && form.state() != form_reader::status::failed) {
            form.finish();
        }
        if (form.state() == form_reader::status::failed) {
            return fail(form.error());
        }
        if (!form.fields_complete()) {
            return fail(malformed_post());
        }

        auto posted =
            authenticate_post(*_authorizer, form.form(), resource->bucket, _rules, _ctx.now());
        if (!posted) {
            return fail(posted.error());
        }
        const auto& auth = posted->auth;

        s3_request req;
        req.method = "PUT";
        req.resource = *resource;
        req.resource.key = posted->key;
        req.source_ip = in.source_ip;
        req.secure_transport = in.secure_transport;
        req.request_id = request_id;
        // The form's fields stand in for a PUT's headers.
        for (const auto& [k, v] : form.form().fields) {
            const auto lk = authz_detail::lower(k);
            if (lk == "policy" || lk == "key" || lk.starts_with("x-amz-signature") ||
                lk == "x-amz-credential" || lk == "x-amz-algorithm" || lk == "x-amz-date" ||
                lk == "success_action_status" || lk == "success_action_redirect" ||
                lk == "redirect" || lk.starts_with("x-ignore-") || lk == "file") {
                continue;
            }
            req.headers.emplace_back(lk == "acl"       ? "x-amz-acl"
                                     : lk == "tagging" ? "x-amz-tagging"
                                                       : k,
                                     v);
        }
        if (!find_header(req.headers, "Content-Type") && !form.form().file_content_type.empty()) {
            req.headers.emplace_back("Content-Type", form.form().file_content_type);
        }

        bucket_state b;
        if (auto e = find_bucket(resource->bucket, auth, req, b)) {
            return fail(*e);
        }
        if (auto e = admit(req, b)) {
            return fail(*e);
        }
        auto facts = facts_for(req, auth, &b);
        facts.operation = "PutObject";
        facts.key = posted->key;
        if (auto e = authorize(facts, auth, b, nullptr, {}, {})) {
            return fail(*e);
        }

        // The rest of the file streams into the PUT path.
        auto state = std::make_shared<std::pair<std::string, bool>>(std::move(file), more);
        auto* reader = &form;
        auto* raw = &in.body;
        req.body = [state, reader, raw](std::string& out) -> aws_rest_xml::result<bool> {
            out.append(state->first);
            state->first.clear();
            if (!state->second) {
                return false;
            }
            std::string chunk;
            auto r = *raw ? (*raw)(chunk) : aws_rest_xml::result<bool>(false);
            if (!r) {
                return r.error();
            }
            state->second = *r;
            reader->feed(chunk, out);
            if (!state->second) {
                reader->finish();
            }
            if (reader->state() == form_reader::status::failed) {
                return reader->error();
            }
            return state->second;
        };
        auto result = put_object(_ctx, req, auth, b);
        if (!result) {
            return fail(result.error());
        }
        if (posted->policy) {
            if (auto e = check_post_length(*posted->policy, form.file_bytes())) {
                // The object is stored; S3 checks the length before, so
                // remove it again rather than leave a refused upload.
                index_command c;
                c.op = index_command::kind::delete_object;
                c.now_ms = _ctx.now_ms();
                c.target = ref_of(b.desc);
                c.key = posted->key;
                c.version_id = result->header("x-amz-version-id");
                (void)_ctx.meta.propose(c);
                return fail(*e);
            }
        }

        s3_response out;
        const auto etag = result->header("ETag").value_or("");
        out.set("ETag", etag);
        if (auto v = result->header("x-amz-version-id")) {
            out.set("x-amz-version-id", *v);
        }
        const auto location =
            "/" + resource->bucket + "/" + aws_rest_xml::url_encode_key(posted->key);
        out.set("Location", location);
        if (auto redirect = form.form().get("success_action_redirect")) {
            out.status = 303;
            out.set("Location", *redirect + (redirect->find('?') == std::string::npos ? "?" : "&") +
                                    "bucket=" + resource->bucket +
                                    "&key=" + aws_rest_xml::url_encode_key(posted->key) +
                                    "&etag=" + aws_rest_xml::url_encode_key(etag));
            return out;
        }
        const auto status = form.form().get("success_action_status").value_or("204");
        if (status == "201") {
            aws_query::xml_writer w;
            w.raw(aws_rest_xml::xml_declaration);
            w.open("PostResponse");
            w.element("Location", location)
                .element("Bucket", resource->bucket)
                .element("Key", posted->key)
                .element("ETag", etag);
            w.close();
            out.status = 201;
            out.body = w.str();
            out.set("Content-Type", "application/xml");
        } else {
            out.status = status == "200" ? 200 : 204;
        }
        return out;
    }

    /// Requirement 13: a request over its prefix's rate is `503 SlowDown`
    /// before it is authorized or touches anything.
    [[nodiscard]] auto admit(const s3_request& req, const bucket_state& b)
        -> std::optional<aws_rest_xml::error> {
        const bool write = req.method != "GET" && req.method != "HEAD";
        const auto prefix = !req.resource.key.empty()
                                ? rate_prefix(req.resource.key)
                                : rate_prefix(req.query.get("prefix").value_or(""));
        const auto rate = write ? b.profile.prefix_put_rate : b.profile.prefix_get_rate;
        if (_rates.admit(b.desc.name, prefix, write, rate, _ctx.now_ms())) {
            return std::nullopt;
        }
        return slow_down();
    }

    service_options _options;
    A* _authorizer;
    handler_context<M> _ctx;
    prefix_rates _rates;
    sigv4::service_rules _rules;
};

}  // namespace kythira::s3
