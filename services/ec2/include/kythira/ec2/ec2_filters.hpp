// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_filters.hpp
/// @brief The filter engine and the paging every `Describe*` shares
///        (`.kiro/specs/ec2-compatible-api/` task 4, Requirement 4.5).
///
/// ### Filters
///
/// A describe names the filters it supports (`filter_names`); a filter
/// outside that set is `InvalidParameterValue` ("The filter 'x' is
/// invalid"), as on EC2. A resource answers a filter name with its values
/// for it (`field_lookup`: the instance's `instance-state-name`, every
/// `private-ip-address` of its interfaces), and the engine matches:
///
/// - the values of one filter are ORed, the filters ANDed;
/// - a value may use `*` (any run, including none) and `?` (one
///   character), and `\` escapes either, as EC2 documents;
/// - a filter sent with no values matches nothing;
/// - `tag:<key>` matches the value of that tag; `tag-key` any tag's key;
///   `tag-value` any tag's value. A describe allows them by naming
///   `tag:`, `tag-key` and `tag-value` among its filters (`tag:` as a
///   prefix).
///
/// ### Paging
///
/// `read_page` reads `MaxResults` in the describe's range and opens
/// `NextToken`, sealed for the operation and the caller's account with the
/// query codec's `marker_sealer`, so a token from another describe, another
/// account or nowhere is `InvalidPaginationToken`. `paginate` cuts a page
/// from items in key order: everything after the token's key, at most
/// `MaxResults`, and a token over the last key returned when more remain.
/// One page is one read of the data layer's state at one index (the
/// caller's job), and a resource created between pages appears on a later
/// page if its key sorts after the token, as on EC2.

#include <kythira/ec2/ec2_tags.hpp>

#include <raft/aws_ec2_protocol.hpp>
#include <raft/aws_query_protocol.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::ec2 {

/// The filter names a describe supports. A name ending in `:` (`tag:`)
/// allows every name with that prefix.
using filter_names = std::set<std::string, std::less<>>;

/// A resource's values for a filter name; empty when it has none.
using field_lookup = std::function<std::vector<std::string>(std::string_view name)>;

/// EC2's filter wildcard match: `*` any run, `?` one character, `\`
/// escapes the next character.
[[nodiscard]] inline auto wildcard_match(std::string_view pattern, std::string_view text) -> bool {
    // Iterative glob with one backtrack point, over a pattern whose escapes
    // are resolved as it is read.
    std::size_t p = 0;
    std::size_t t = 0;
    std::size_t star_p = std::string_view::npos;
    std::size_t star_t = 0;
    while (t < text.size()) {
        if (p < pattern.size()) {
            const char c = pattern[p];
            if (c == '*') {
                star_p = ++p;
                star_t = t;
                continue;
            }
            if (c == '?') {
                ++p;
                ++t;
                continue;
            }
            const bool escaped = c == '\\' && p + 1 < pattern.size();
            const char lit = escaped ? pattern[p + 1] : c;
            if (lit == text[t]) {
                p += escaped ? 2 : 1;
                ++t;
                continue;
            }
        }
        if (star_p == std::string_view::npos) {
            return false;
        }
        p = star_p;
        t = ++star_t;
    }
    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

/// The filters of one describe request, checked against what it supports.
class filter_set {
public:
    filter_set() = default;

    /// `Filter.N` of `p`, or `InvalidParameterValue` for a filter the
    /// describe does not support.
    [[nodiscard]] static auto read(const aws_ec2::params& p, const filter_names& supported)
        -> aws_ec2::result<filter_set> {
        auto fs = aws_ec2::filters(p);
        if (!fs) {
            return fs.err();
        }
        for (const auto& f : *fs) {
            if (!allowed(f.name, supported)) {
                return aws_ec2::make_error(aws_ec2::codes::invalid_parameter_value,
                                           "The filter '" + f.name + "' is invalid");
            }
        }
        filter_set out;
        out._filters = *fs;
        return out;
    }

    [[nodiscard]] auto empty() const -> bool { return _filters.empty(); }

    /// Whether a resource with `fields` and `tags` passes every filter.
    [[nodiscard]] auto matches(const field_lookup& fields, const tag_map& tags) const -> bool {
        for (const auto& f : _filters) {
            if (!one(f, fields, tags)) {
                return false;
            }
        }
        return true;
    }

private:
    std::vector<aws_ec2::filter> _filters;

    [[nodiscard]] static auto allowed(std::string_view name, const filter_names& supported)
        -> bool {
        if (!name.ends_with(':') && supported.contains(name)) {
            return true;
        }
        const auto colon = name.find(':');
        return colon != std::string_view::npos && colon + 1 < name.size() &&
               supported.contains(name.substr(0, colon + 1));
    }

    [[nodiscard]] static auto any(const std::vector<std::string>& patterns,
                                  const std::vector<std::string>& values) -> bool {
        for (const auto& v : values) {
            for (const auto& pat : patterns) {
                if (wildcard_match(pat, v)) {
                    return true;
                }
            }
        }
        return false;
    }

    [[nodiscard]] static auto one(const aws_ec2::filter& f, const field_lookup& fields,
                                  const tag_map& tags) -> bool {
        if (f.values.empty()) {
            return false;
        }
        if (f.name.starts_with("tag:")) {
            const auto it = tags.find(std::string_view(f.name).substr(4));
            return it != tags.end() && any(f.values, {it->second});
        }
        if (f.name == "tag-key" || f.name == "tag-value") {
            std::vector<std::string> vs;
            vs.reserve(tags.size());
            for (const auto& [k, v] : tags) {
                vs.push_back(f.name == "tag-key" ? k : v);
            }
            return any(f.values, vs);
        }
        return any(f.values, fields ? fields(f.name) : std::vector<std::string>{});
    }
};

/// What a describe's page request asks for.
struct page_request {
    std::optional<std::size_t> _max;
    /// The last key of the previous page.
    std::optional<std::string> _after;
};

/// The context a describe's tokens are sealed for: the operation and the
/// caller's account, so a token never crosses either.
[[nodiscard]] inline auto page_context(std::string_view operation, std::string_view account)
    -> std::string {
    return std::string(operation) + "\n" + std::string(account);
}

/// `MaxResults` in `[lo, hi]` and `NextToken` sealed for `context`.
[[nodiscard]] inline auto read_page(const aws_ec2::params& p,
                                    const aws_query::marker_sealer& sealer,
                                    std::string_view context, std::int64_t lo, std::int64_t hi)
    -> aws_ec2::result<page_request> {
    const auto max = aws_ec2::max_results(p, lo, hi);
    if (!max) {
        return max.err();
    }
    auto after = aws_ec2::open_next_token(p, sealer, context);
    if (!after) {
        return after.err();
    }
    page_request out;
    if (*max) {
        out._max = static_cast<std::size_t>(**max);
    }
    out._after = *after;
    return out;
}

/// One page of a describe's answer.
template<class T> struct page {
    std::vector<T> _items;
    std::optional<std::string> _next_token;
};

/// Cuts a page from `items`, (key, item) pairs sorted by key, that already
/// passed the filters. `MaxResults` absent answers everything after the
/// token.
template<class T>
[[nodiscard]] auto paginate(const std::vector<std::pair<std::string, T>>& items,
                            const page_request& req, const aws_query::marker_sealer& sealer,
                            std::string_view context) -> page<T> {
    page<T> out;
    auto it = items.begin();
    if (req._after) {
        it = std::upper_bound(items.begin(), items.end(), *req._after,
                              [](const std::string& k, const auto& e) { return k < e.first; });
    }
    for (; it != items.end(); ++it) {
        if (req._max && out._items.size() == *req._max) {
            out._next_token = sealer.seal(context, std::prev(it)->first);
            break;
        }
        out._items.push_back(it->second);
    }
    return out;
}

/// EC2's `<nextToken>` field, empty when there is no next page.
[[nodiscard]] inline auto next_token_xml(const std::optional<std::string>& token) -> std::string {
    if (!token) {
        return {};
    }
    return "<nextToken>" + aws_query::xml_escape(*token) + "</nextToken>";
}

}  // namespace kythira::ec2
