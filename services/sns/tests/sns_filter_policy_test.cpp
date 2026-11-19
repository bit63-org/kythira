// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// SNS filter policies (`.kiro/specs/sns-compatible-notifications/` task 5,
// Requirement 6.2): every operator in both scopes, AND across keys and OR
// within one, `$or` at the top and nested, arrays on either side, the
// typing rules for attribute data types, and the grammar and limit errors
// `parse` answers.

#define BOOST_TEST_MODULE sns_filter_policy_test
#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_filter_policy.hpp>

#include <string>
#include <string_view>

using namespace kythira::sns;

namespace {

auto policy(std::string_view text, filter_scope scope = filter_scope::message_attributes)
    -> filter_policy {
    auto p = filter_policy::parse(text, scope);
    BOOST_REQUIRE_MESSAGE(p.has_value(),
                          std::string(text) + ": " + (p.has_value() ? "" : p.error()._message));
    return *p;
}

auto error(std::string_view text, filter_scope scope = filter_scope::message_attributes)
    -> std::string {
    auto p = filter_policy::parse(text, scope);
    BOOST_REQUIRE_MESSAGE(!p.has_value(), std::string(text) + " parsed");
    BOOST_CHECK_EQUAL(p.error()._code, "InvalidParameter");
    return p.error()._message;
}

auto str(std::string v) -> message_attribute {
    return {"String", std::move(v), std::nullopt};
}
auto num(std::string v) -> message_attribute {
    return {"Number", std::move(v), std::nullopt};
}
auto arr(std::string v) -> message_attribute {
    return {"String.Array", std::move(v), std::nullopt};
}

auto attrs(std::initializer_list<std::pair<const std::string, message_attribute>> l)
    -> message_attributes {
    return message_attributes(l);
}

auto body(std::string_view p, std::string_view b) -> bool {
    return policy(p, filter_scope::message_body).matches_body(b);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(attribute_scope)

BOOST_AUTO_TEST_CASE(exact_strings_and_numbers_respect_data_types) {
    const auto p = policy(R"({"color": ["red", "blue"], "size": [10]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"color", str("red")}, {"size", num("10")}})));
    BOOST_CHECK(p.matches_attributes(attrs({{"color", str("blue")}, {"size", num("10.000")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"color", str("green")}, {"size", num("10")}})));
    // Every key must be present and match.
    BOOST_CHECK(!p.matches_attributes(attrs({{"color", str("red")}})));
    // A String "10" is not the number 10, nor a Number "red" a string.
    BOOST_CHECK(!p.matches_attributes(attrs({{"color", str("red")}, {"size", str("10")}})));
    // Custom data type suffixes keep the base type.
    BOOST_CHECK(p.matches_attributes(
        attrs({{"color", {"String.custom", "red", std::nullopt}}, {"size", num("1e1")}})));
}

BOOST_AUTO_TEST_CASE(binary_attributes_are_ignored) {
    const auto p = policy(R"({"b": [{"exists": false}]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"b", {"Binary", std::nullopt, "abc"}}})));
    BOOST_CHECK(!policy(R"({"b": [{"exists": true}]})")
                     .matches_attributes(attrs({{"b", {"Binary", std::nullopt, "abc"}}})));
}

BOOST_AUTO_TEST_CASE(string_arrays_match_any_element) {
    const auto p = policy(R"({"tags": ["urgent"]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"tags", arr(R"(["low", "urgent"])")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"tags", arr(R"(["low"])")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"tags", arr("not json")}})));
    // Numbers and booleans inside an array compare by type.
    BOOST_CHECK(policy(R"({"t": [3]})").matches_attributes(attrs({{"t", arr("[1, 3]")}})));
    BOOST_CHECK(policy(R"({"t": [true]})").matches_attributes(attrs({{"t", arr("[true]")}})));
    BOOST_CHECK(policy(R"({"t": [null]})").matches_attributes(attrs({{"t", arr("[null]")}})));
}

BOOST_AUTO_TEST_CASE(string_operators) {
    const auto a = attrs({{"s", str("Order-Shipped")}});
    BOOST_CHECK(policy(R"({"s": [{"prefix": "Order-"}]})").matches_attributes(a));
    BOOST_CHECK(!policy(R"({"s": [{"prefix": "order-"}]})").matches_attributes(a));
    BOOST_CHECK(policy(R"({"s": [{"suffix": "Shipped"}]})").matches_attributes(a));
    BOOST_CHECK(
        policy(R"({"s": [{"equals-ignore-case": "order-SHIPPED"}]})").matches_attributes(a));
    BOOST_CHECK(policy(R"({"s": [{"wildcard": "Order-*ed"}]})").matches_attributes(a));
    BOOST_CHECK(policy(R"({"s": [{"wildcard": "*"}]})").matches_attributes(a));
    BOOST_CHECK(!policy(R"({"s": [{"wildcard": "Order*x"}]})").matches_attributes(a));
    BOOST_CHECK(
        policy(R"({"s": [{"wildcard": "a\\*b"}]})").matches_attributes(attrs({{"s", str("a*b")}})));
    BOOST_CHECK(!policy(R"({"s": [{"wildcard": "a\\*b"}]})")
                     .matches_attributes(attrs({{"s", str("axxb")}})));
    // String operators never match a number.
    BOOST_CHECK(
        !policy(R"({"n": [{"prefix": "1"}]})").matches_attributes(attrs({{"n", num("10")}})));
}

BOOST_AUTO_TEST_CASE(anything_but) {
    const auto p = policy(R"({"c": [{"anything-but": ["red", "blue"]}]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"c", str("green")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"c", str("red")}})));
    // The key must be present.
    BOOST_CHECK(!p.matches_attributes(attrs({})));
    const auto n = policy(R"({"n": [{"anything-but": 5}]})");
    BOOST_CHECK(n.matches_attributes(attrs({{"n", num("6")}})));
    BOOST_CHECK(!n.matches_attributes(attrs({{"n", num("5.0")}})));
    const auto pre = policy(R"({"c": [{"anything-but": {"prefix": "tmp-"}}]})");
    BOOST_CHECK(pre.matches_attributes(attrs({{"c", str("keep")}})));
    BOOST_CHECK(!pre.matches_attributes(attrs({{"c", str("tmp-1")}})));
    const auto suf = policy(R"({"c": [{"anything-but": {"suffix": ".log"}}]})");
    BOOST_CHECK(!suf.matches_attributes(attrs({{"c", str("a.log")}})));
}

BOOST_AUTO_TEST_CASE(numeric_ranges) {
    const auto p = policy(R"({"price": [{"numeric": [">", 0, "<=", 100]}]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"price", num("100")}})));
    BOOST_CHECK(p.matches_attributes(attrs({{"price", num("0.00001")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"price", num("0")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"price", num("100.5")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"price", str("50")}})));
    // Five decimal places: these are equal to SNS.
    BOOST_CHECK(policy(R"({"x": [{"numeric": ["=", 1.000001]}]})")
                    .matches_attributes(attrs({{"x", num("1")}})));
    BOOST_CHECK(policy(R"({"x": [{"numeric": [">=", -5]}]})")
                    .matches_attributes(attrs({{"x", num("-5")}})));
}

BOOST_AUTO_TEST_CASE(exists) {
    const auto yes = policy(R"({"k": [{"exists": true}]})");
    const auto no = policy(R"({"k": [{"exists": false}]})");
    BOOST_CHECK(yes.matches_attributes(attrs({{"k", str("")}})));
    BOOST_CHECK(!yes.matches_attributes(attrs({})));
    BOOST_CHECK(no.matches_attributes(attrs({{"other", str("x")}})));
    BOOST_CHECK(!no.matches_attributes(attrs({{"k", str("x")}})));
}

BOOST_AUTO_TEST_CASE(cidr_v4_and_v6) {
    const auto p = policy(R"({"ip": [{"cidr": "10.0.0.0/24"}, {"cidr": "2001:db8::/32"}]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"ip", str("10.0.0.255")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"ip", str("10.0.1.0")}})));
    BOOST_CHECK(p.matches_attributes(attrs({{"ip", str("2001:db8:1::5")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"ip", str("2001:db9::1")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"ip", str("not an ip")}})));
    BOOST_CHECK(policy(R"({"ip": [{"cidr": "192.168.1.128/25"}]})")
                    .matches_attributes(attrs({{"ip", str("192.168.1.200")}})));
    BOOST_CHECK(!policy(R"({"ip": [{"cidr": "192.168.1.128/25"}]})")
                     .matches_attributes(attrs({{"ip", str("192.168.1.100")}})));
}

BOOST_AUTO_TEST_CASE(or_across_keys) {
    const auto p = policy(
        R"({"source": ["shop"], "$or": [{"color": ["red"]}, {"size": [{"numeric": [">", 5]}]}]})");
    BOOST_CHECK(p.matches_attributes(attrs({{"source", str("shop")}, {"color", str("red")}})));
    BOOST_CHECK(p.matches_attributes(attrs({{"source", str("shop")}, {"size", num("6")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"source", str("shop")}, {"size", num("4")}})));
    BOOST_CHECK(!p.matches_attributes(attrs({{"source", str("web")}, {"color", str("red")}})));
}

BOOST_AUTO_TEST_CASE(empty_policy_matches_everything) {
    BOOST_CHECK(policy("{}").matches_attributes(attrs({})));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(payload_scope)

BOOST_AUTO_TEST_CASE(nested_keys) {
    const auto* p = R"({"order": {"status": ["shipped"], "total": [{"numeric": [">", 10]}]}})";
    BOOST_CHECK(body(p, R"({"order": {"status": "shipped", "total": 12}})"));
    BOOST_CHECK(!body(p, R"({"order": {"status": "shipped", "total": 8}})"));
    BOOST_CHECK(!body(p, R"({"status": "shipped", "total": 12})"));
    BOOST_CHECK(!body(p, "not json"));
    BOOST_CHECK(!body(p, R"(["order"])"));
}

BOOST_AUTO_TEST_CASE(arrays_in_the_body) {
    const auto* p = R"({"items": {"sku": ["A1"]}})";
    BOOST_CHECK(body(p, R"({"items": [{"sku": "B2"}, {"sku": "A1"}]})"));
    BOOST_CHECK(!body(p, R"({"items": [{"sku": "B2"}]})"));
    BOOST_CHECK(body(R"({"tags": ["x"]})", R"({"tags": ["y", "x"]})"));
}

BOOST_AUTO_TEST_CASE(booleans_null_and_exists) {
    BOOST_CHECK(body(R"({"ok": [true]})", R"({"ok": true})"));
    BOOST_CHECK(!body(R"({"ok": [true]})", R"({"ok": "true"})"));
    BOOST_CHECK(body(R"({"v": [null]})", R"({"v": null})"));
    BOOST_CHECK(body(R"({"a": {"b": [{"exists": false}]}})", R"({"a": {}})"));
    BOOST_CHECK(!body(R"({"a": {"b": [{"exists": true}]}})", R"({"a": {}})"));
    // An object is not a leaf, so exists does not see it.
    BOOST_CHECK(!body(R"({"a": [{"exists": true}]})", R"({"a": {"b": 1}})"));
}

BOOST_AUTO_TEST_CASE(nested_or) {
    const auto* p = R"({"o": {"$or": [{"a": ["1"]}, {"b": ["2"]}]}})";
    BOOST_CHECK(body(p, R"({"o": {"b": "2"}})"));
    BOOST_CHECK(!body(p, R"({"o": {"c": "3"}, "b": "2"})"));
}

BOOST_AUTO_TEST_CASE(matches_reads_the_scope) {
    published_message m;
    m._message = R"({"kind": "a"})";
    m._attributes.emplace("kind", str("b"));
    BOOST_CHECK(policy(R"({"kind": ["a"]})", filter_scope::message_body).matches(m));
    BOOST_CHECK(policy(R"({"kind": ["b"]})").matches(m));
    BOOST_CHECK(parse_filter_scope("MessageBody") == filter_scope::message_body);
    BOOST_CHECK(parse_filter_scope("") == filter_scope::message_attributes);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(grammar)

BOOST_AUTO_TEST_CASE(nested_policies_need_payload_scope) {
    BOOST_CHECK_EQUAL(error(R"({"a": {"b": ["x"]}})"),
                      "Invalid parameter: Filter policy scope MessageAttributes does not support "
                      "nested filter policy");
}

BOOST_AUTO_TEST_CASE(bad_shapes) {
    const std::string p = "Invalid parameter: FilterPolicy: ";
    BOOST_CHECK_EQUAL(error("not json"), p + "failed to parse JSON");
    BOOST_CHECK_EQUAL(error("[]"), p + "Filter policy must be a JSON object");
    BOOST_CHECK_EQUAL(error(R"({"a": "x"})"), p + "\"a\" must be an object or an array");
    BOOST_CHECK_EQUAL(error(R"({"a": []})"), p + "Empty arrays are not allowed");
    BOOST_CHECK_EQUAL(error(R"({"a": [["x"]]})"),
                      p + "Match value must be String, number, true, false, or null");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"regex": "x"}]})"), p + "Unrecognized match type regex");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"prefix": 1}]})"),
                      p + "prefix match pattern must be a string");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"exists": "yes"}]})"),
                      p + "exists match pattern must be either true or false.");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"prefix": "x", "suffix": "y"}]})"),
                      p + "Only one key allowed in match expression");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"wildcard": "a**b"}]})"),
                      p + "Consecutive wildcard characters at pos 2");
    BOOST_CHECK_EQUAL(error(R"({"$or": [{"a": ["x"]}]})"),
                      p + "Value of $or must be an array of at least two objects");
    BOOST_CHECK_EQUAL(error(R"({"a": {}})", filter_scope::message_body),
                      p + "Empty objects are not allowed");
}

BOOST_AUTO_TEST_CASE(numeric_expressions) {
    const std::string p = "Invalid parameter: FilterPolicy: ";
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": 5}]})"),
                      p + "Value of numeric must be an array.");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": ["<", "x"]}]})"),
                      p + "Value of < must be numeric");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": ["~", 1]}]})"),
                      p + "Unrecognized numeric range operator: ~");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": [">", 1, "<", 2, "=", 3]}]})"),
                      p + "Too many elements in numeric expression");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": ["<", 1, ">", 0]}]})"),
                      p + "Bad numeric range operator: <");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"numeric": [">", 5, "<", 5]}]})"),
                      p + "Bottom must be less than top");
    BOOST_CHECK_EQUAL(error(R"({"a": [2000000000]})"),
                      p + "Numeric values must be between -1000000000 and 1000000000");
}

BOOST_AUTO_TEST_CASE(cidr_errors) {
    const std::string p = "Invalid parameter: FilterPolicy: ";
    BOOST_CHECK_EQUAL(error(R"({"a": [{"cidr": "10.0.0.0"}]})"),
                      p + "Malformed CIDR, one '/' required");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"cidr": "10.0.0/8"}]})"),
                      p + "Nonstandard IP address: 10.0.0");
    BOOST_CHECK_EQUAL(error(R"({"a": [{"cidr": "10.0.0.0/33"}]})"),
                      p + "Malformed CIDR, mask bits must be an integer");
}

BOOST_AUTO_TEST_CASE(limits) {
    const std::string p = "Invalid parameter: FilterPolicy: ";
    BOOST_CHECK_EQUAL(error(R"({"a":["1"],"b":["1"],"c":["1"],"d":["1"],"e":["1"],"f":["1"]})"),
                      p + "Filter policy can not have more than 5 keys");
    // Five keys on each side of an $or is still five on any one path.
    policy(
        R"({"a":["1"],"b":["1"],"c":["1"],"$or":[{"d":["1"],"e":["1"]},{"f":["1"],"g":["1"]}]})");
    // 10 x 15 = 150 combinations is the most allowed.
    std::string ten = "[";
    std::string fifteen = "[";
    for (int i = 0; i < 15; ++i) {
        if (i < 10) {
            ten += (i != 0 ? "," : "") + std::to_string(i);
        }
        fifteen += (i != 0 ? "," : "") + std::to_string(i);
    }
    ten += "]";
    fifteen += "]";
    BOOST_CHECK_EQUAL(policy(R"({"a":)" + ten + R"(,"b":)" + fifteen + "}").combinations(), 150U);
    BOOST_CHECK_EQUAL(error(R"({"a":)" + ten + R"(,"b":)" + fifteen + R"(,"c":[1,2]})"),
                      p + "Filter policy is too complex");
    // An $or adds its branches' combinations.
    BOOST_CHECK_EQUAL(policy(R"({"a":[1,2],"$or":[{"b":[1,2,3]},{"c":[1]}]})").combinations(), 8U);
    BOOST_CHECK_EQUAL(error(std::string(k_max_filter_policy_bytes + 1, ' ')),
                      p + "Filter policy is too long");
}

BOOST_AUTO_TEST_SUITE_END()
