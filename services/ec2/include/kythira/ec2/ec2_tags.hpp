// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_tags.hpp
/// @brief EC2 tags: validation, `CreateTags` and `DeleteTags` semantics,
///        and `TagSpecifications` on create
///        (`.kiro/specs/ec2-compatible-api/` task 4, Requirement 4.4).
///
/// EC2's tag rules, from the EC2 User Guide's "Tag restrictions":
///
/// - at most 50 tags per resource;
/// - a key is 1 to 127 Unicode characters, a value 0 to 255 (characters,
///   not bytes: a key of 127 accented letters is accepted);
/// - keys and values are case-sensitive;
/// - keys beginning with `aws:` (any case) are reserved: a request cannot
///   create, change or delete one.
///
/// `CreateTags` adds or overwrites; a tag sent without a value gets the
/// empty value. `DeleteTags` with a value deletes the tag only while it has
/// that value (the empty value matches only the empty value); without a
/// value it deletes the key whatever its value; a key the resource lacks is
/// not an error. The limit counts the tags after the change, so replacing a
/// value on a resource at 50 tags is allowed. Messages follow EC2's; task
/// 19's recorded responses pin their exact wording.

#include <kythira/ec2/ec2_front_end.hpp>

#include <raft/aws_ec2_protocol.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::ec2 {

inline constexpr std::size_t k_max_tags_per_resource = 50;
inline constexpr std::size_t k_max_tag_key_chars = 127;
inline constexpr std::size_t k_max_tag_value_chars = 255;

/// A resource's tags, by key.
using tag_map = std::map<std::string, std::string, std::less<>>;

namespace tags_detail {

/// Unicode characters in UTF-8 `s` (continuation bytes are not counted;
/// malformed input counts its lead bytes, which is never fewer than the
/// characters a valid reading would give).
[[nodiscard]] constexpr auto characters(std::string_view s) -> std::size_t {
    std::size_t n = 0;
    for (const char c : s) {
        if ((static_cast<unsigned char>(c) & 0xC0U) != 0x80U) {
            ++n;
        }
    }
    return n;
}

[[nodiscard]] inline auto reserved(std::string_view key) -> bool {
    if (key.size() < 4) {
        return false;
    }
    const auto lower = [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    return lower(key[0]) == 'a' && lower(key[1]) == 'w' && lower(key[2]) == 's' && key[3] == ':';
}

[[nodiscard]] inline auto invalid(std::string message) -> aws_ec2::error {
    return aws_ec2::make_error(aws_ec2::codes::invalid_parameter_value, std::move(message));
}

}  // namespace tags_detail

/// The error for one tag a request sends, or nullopt.
[[nodiscard]] inline auto check_tag(const aws_ec2::tag& t) -> std::optional<aws_ec2::error> {
    if (t.key.empty()) {
        return tags_detail::invalid("Tag keys must not be empty.");
    }
    if (tags_detail::characters(t.key) > k_max_tag_key_chars) {
        return tags_detail::invalid("Tag key exceeds the maximum length of 127 characters.");
    }
    if (t.value && tags_detail::characters(*t.value) > k_max_tag_value_chars) {
        return tags_detail::invalid("Tag value exceeds the maximum length of 255 characters.");
    }
    if (tags_detail::reserved(t.key)) {
        return tags_detail::invalid("Tag keys starting with 'aws:' are reserved for internal use.");
    }
    return std::nullopt;
}

/// The error for a list of tags a request sends, or nullopt.
[[nodiscard]] inline auto check_tags(const std::vector<aws_ec2::tag>& tags)
    -> std::optional<aws_ec2::error> {
    for (const auto& t : tags) {
        if (auto e = check_tag(t)) {
            return e;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto tag_limit_exceeded() -> aws_ec2::error {
    return aws_ec2::make_error("TagLimitExceeded",
                               "The maximum number of Tags for a resource has been reached.");
}

/// `CreateTags` on one resource: `current` with `tags` added or replaced,
/// or the error (and `current` unchanged).
[[nodiscard]] inline auto create_tags(tag_map& current, const std::vector<aws_ec2::tag>& tags)
    -> std::optional<aws_ec2::error> {
    if (auto e = check_tags(tags)) {
        return e;
    }
    auto next = current;
    for (const auto& t : tags) {
        next.insert_or_assign(t.key, t.value.value_or(std::string()));
    }
    if (next.size() > k_max_tags_per_resource) {
        return tag_limit_exceeded();
    }
    current = std::move(next);
    return std::nullopt;
}

/// `DeleteTags` on one resource. An empty `tags` deletes every tag but
/// the reserved ones, as EC2 does when no `Tag.N` is sent.
[[nodiscard]] inline auto delete_tags(tag_map& current, const std::vector<aws_ec2::tag>& tags)
    -> std::optional<aws_ec2::error> {
    for (const auto& t : tags) {
        if (t.key.empty()) {
            return tags_detail::invalid("Tag keys must not be empty.");
        }
        if (tags_detail::reserved(t.key)) {
            return tags_detail::invalid(
                "Tag keys starting with 'aws:' are reserved for internal use.");
        }
    }
    if (tags.empty()) {
        std::erase_if(current, [](const auto& kv) { return !tags_detail::reserved(kv.first); });
        return std::nullopt;
    }
    for (const auto& t : tags) {
        const auto it = current.find(t.key);
        if (it != current.end() && (!t.value || it->second == *t.value)) {
            current.erase(it);
        }
    }
    return std::nullopt;
}

/// A tag list as authorization's request tags.
[[nodiscard]] inline auto to_pairs(const std::vector<aws_ec2::tag>& tags) -> tag_pairs {
    tag_pairs out;
    out.reserve(tags.size());
    for (const auto& t : tags) {
        out.emplace_back(t.key, t.value.value_or(std::string()));
    }
    return out;
}

[[nodiscard]] inline auto to_pairs(const tag_map& tags) -> tag_pairs {
    return {tags.begin(), tags.end()};
}

/// The tags a create puts on each kind of resource it makes, by resource
/// type, from `TagSpecification.N`. `allowed` is what the operation creates
/// (`instance`, `volume`, `network-interface` for RunInstances); any other
/// type is refused, and every tag is checked, before anything is created.
[[nodiscard]] inline auto tags_on_create(const aws_ec2::params& p,
                                         const std::set<std::string_view>& allowed)
    -> aws_ec2::result<std::map<std::string, tag_map, std::less<>>> {
    auto specs = aws_ec2::tag_specifications(p);
    if (!specs) {
        return specs.err();
    }
    std::map<std::string, tag_map, std::less<>> out;
    for (const auto& s : *specs) {
        if (!allowed.contains(s.resource_type)) {
            return tags_detail::invalid("'" + s.resource_type +
                                        "' is not a valid taggable resource type for this "
                                        "operation.");
        }
        tag_map m;
        if (auto e = create_tags(m, s.tags)) {
            return *e;
        }
        out.emplace(s.resource_type, std::move(m));
    }
    return out;
}

}  // namespace kythira::ec2
