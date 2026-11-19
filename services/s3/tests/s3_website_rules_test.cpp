// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_website_rules_test.cpp
/// @brief CORS and website configurations (`s3_cors_rules.hpp`,
///        `s3_website_rules.hpp`; .kiro/specs/s3-compatible-storage/
///        task 15, Requirements 6.1 and 12.4).
///
/// Each configuration's XML both ways and S3's checks on it; which CORS
/// rule answers a request and the headers it adds; which routing rule
/// matches before and after an error and where it redirects; and the
/// website endpoint's HTML error page.

#define BOOST_TEST_MODULE s3_website_rules_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_cors_rules.hpp>
#include <kythira/s3/s3_website_rules.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace s3 = kythira::s3;

auto contains(const std::string& s, std::string_view part) -> bool {
    return s.find(part) != std::string::npos;
}

auto header(const std::vector<std::pair<std::string, std::string>>& h, std::string_view name)
    -> std::optional<std::string> {
    for (const auto& [k, v] : h) {
        if (k == name) {
            return v;
        }
    }
    return std::nullopt;
}

const std::string k_cors = R"(<CORSConfiguration>
  <CORSRule>
    <ID>app</ID>
    <AllowedOrigin>https://app.example.com</AllowedOrigin>
    <AllowedOrigin>https://*.example.org</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedHeader>x-amz-*</AllowedHeader>
    <AllowedHeader>Content-Type</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <ExposeHeader>x-amz-version-id</ExposeHeader>
    <MaxAgeSeconds>3000</MaxAgeSeconds>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
  </CORSRule>
</CORSConfiguration>)";

auto cors_rule_xml(std::string_view inner) -> std::string {
    return "<CORSConfiguration><CORSRule>" + std::string(inner) + "</CORSRule></CORSConfiguration>";
}

auto website(std::string_view inner) -> std::string {
    return "<WebsiteConfiguration>" + std::string(inner) + "</WebsiteConfiguration>";
}

}  // namespace

BOOST_AUTO_TEST_CASE(cors_configurations_round_trip) {
    auto c = s3::parse_cors_configuration(k_cors);
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->rules.size() == 2U);
    BOOST_TEST(c->rules[0].id == "app");
    BOOST_TEST(c->rules[0].allowed_origins.size() == 2U);
    BOOST_TEST(c->rules[0].max_age_seconds.value_or(0) == 3000U);
    BOOST_TEST(!c->rules[1].max_age_seconds.has_value());
    const auto xml = s3::cors_xml(*c);
    BOOST_TEST(contains(xml, "<AllowedHeader>x-amz-*</AllowedHeader>"));
    auto again = s3::parse_cors_configuration(xml);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(s3::cors_xml(*again) == xml);
    BOOST_TEST(!s3::load_cors("not xml").has_value());
}

BOOST_AUTO_TEST_CASE(cors_configurations_are_checked_as_s3_checks_them) {
    const auto code = [](const std::string& xml) {
        auto c = s3::parse_cors_configuration(xml);
        return c ? std::string{} : c.error().code;
    };
    BOOST_TEST(code("<CORSConfiguration/>") == "MalformedXML");
    BOOST_TEST(code("<Other/>") == "MalformedXML");
    BOOST_TEST(code(cors_rule_xml("<AllowedMethod>GET</AllowedMethod>")) == "MalformedXML");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>*</AllowedOrigin>")) == "MalformedXML");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET"
                                  "</AllowedMethod><Bogus/>")) == "MalformedXML");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET"
                                  "</AllowedMethod><MaxAgeSeconds>-1</MaxAgeSeconds>")) ==
               "MalformedXML");

    auto patch = s3::parse_cors_configuration(
        cors_rule_xml("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod>"));
    BOOST_REQUIRE(!patch.has_value());
    BOOST_TEST(patch.error().code == "InvalidRequest");
    BOOST_TEST(patch.error().message ==
               "Found unsupported HTTP method in CORS config. Unsupported method is PATCH");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>https://*.*.com</AllowedOrigin>"
                                  "<AllowedMethod>GET</AllowedMethod>")) == "InvalidRequest");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET"
                                  "</AllowedMethod><AllowedHeader>*-*</AllowedHeader>")) ==
               "InvalidRequest");
    BOOST_TEST(code(cors_rule_xml("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET"
                                  "</AllowedMethod><ExposeHeader>*</ExposeHeader>")) ==
               "InvalidRequest");

    std::string many = "<CORSConfiguration>";
    for (int i = 0; i < 101; ++i) {
        many +=
            "<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>"
            "</CORSRule>";
    }
    many += "</CORSConfiguration>";
    BOOST_TEST(code(many) == "MalformedXML");
}

BOOST_AUTO_TEST_CASE(the_first_matching_cors_rule_answers) {
    const auto c = s3::parse_cors_configuration(k_cors).value();
    const auto* first = &c.rules[0];
    const auto* second = &c.rules[1];
    BOOST_TEST(s3::match_cors_rule(c, "https://app.example.com", "PUT") == first);
    BOOST_TEST(s3::match_cors_rule(c, "https://a.example.org", "GET") == first);
    // The wildcard stands for at least nothing, never for the dot itself.
    BOOST_TEST(s3::match_cors_rule(c, "https://example.org", "PUT") == nullptr);
    // Origins match case-sensitively.
    BOOST_TEST(s3::match_cors_rule(c, "https://APP.example.com", "PUT") == nullptr);
    BOOST_TEST(s3::match_cors_rule(c, "https://evil.test", "GET") == second);
    BOOST_TEST(s3::match_cors_rule(c, "https://evil.test", "DELETE") == nullptr);
    // Requested headers match case-insensitively, every one of them.
    BOOST_TEST(s3::match_cors_rule(c, "https://app.example.com", "PUT",
                                   {"X-Amz-Date", "content-type"}) == first);
    BOOST_TEST(s3::match_cors_rule(c, "https://app.example.com", "PUT",
                                   {"x-amz-date", "authorization"}) == nullptr);
    // The second rule allows no headers at all.
    BOOST_TEST(s3::match_cors_rule(c, "https://evil.test", "GET", {"x-amz-date"}) == nullptr);
    BOOST_TEST(s3::split_header_list(" a, ,B ,c") == (std::vector<std::string>{"a", "B", "c"}));
}

BOOST_AUTO_TEST_CASE(cors_headers_name_the_origin_unless_any_origin_is_allowed) {
    const auto c = s3::parse_cors_configuration(k_cors).value();
    const auto pre = s3::cors_headers(c.rules[0], "https://app.example.com",
                                      std::vector<std::string>{"X-Amz-Date", "Content-Type"});
    BOOST_TEST(header(pre, "Access-Control-Allow-Origin").value() == "https://app.example.com");
    BOOST_TEST(header(pre, "Access-Control-Allow-Methods").value() == "GET, PUT");
    BOOST_TEST(header(pre, "Access-Control-Allow-Headers").value() == "x-amz-date, content-type");
    BOOST_TEST(header(pre, "Access-Control-Expose-Headers").value() == "ETag, x-amz-version-id");
    BOOST_TEST(header(pre, "Access-Control-Max-Age").value() == "3000");
    BOOST_TEST(header(pre, "Access-Control-Allow-Credentials").value() == "true");

    const auto actual = s3::cors_headers(c.rules[1], "https://evil.test", std::nullopt);
    BOOST_TEST(header(actual, "Access-Control-Allow-Origin").value() == "*");
    BOOST_TEST(!header(actual, "Access-Control-Allow-Headers").has_value());
    BOOST_TEST(!header(actual, "Access-Control-Allow-Credentials").has_value());
    BOOST_TEST(!header(actual, "Access-Control-Max-Age").has_value());
}

BOOST_AUTO_TEST_CASE(website_configurations_round_trip) {
    const auto xml = website(R"(<IndexDocument><Suffix>index.html</Suffix></IndexDocument>
      <ErrorDocument><Key>error.html</Key></ErrorDocument>
      <RoutingRules>
        <RoutingRule>
          <Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>
          <Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect>
        </RoutingRule>
        <RoutingRule>
          <Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>
          <Redirect><HostName>fallback.example.com</HostName><Protocol>https</Protocol>
            <HttpRedirectCode>302</HttpRedirectCode><ReplaceKeyWith>missing.html</ReplaceKeyWith>
          </Redirect>
        </RoutingRule>
      </RoutingRules>)");
    auto c = s3::parse_website_configuration(xml);
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error().message));
    BOOST_TEST(c->index_suffix == "index.html");
    BOOST_TEST(c->error_document.value() == "error.html");
    BOOST_TEST(c->routing_rules.size() == 2U);
    BOOST_TEST(c->routing_rules[1].redirect.http_redirect_code.value() == 302U);
    const auto out = s3::website_xml(*c);
    auto again = s3::parse_website_configuration(out);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(s3::website_xml(*again) == out);

    auto all = s3::parse_website_configuration(
        website("<RedirectAllRequestsTo><HostName>example.com</HostName></RedirectAllRequestsTo>"));
    BOOST_REQUIRE(all.has_value());
    BOOST_TEST(all->redirect_all->host_name == "example.com");
    BOOST_TEST(contains(s3::website_xml(*all), "<RedirectAllRequestsTo><HostName>example.com"));
    BOOST_TEST(!s3::load_website("<WebsiteConfiguration/>").has_value());
}

BOOST_AUTO_TEST_CASE(website_configurations_are_checked_as_s3_checks_them) {
    const auto error = [](const std::string& inner) {
        auto c = s3::parse_website_configuration(website(inner));
        return c ? std::pair<std::string, std::string>{}
                 : std::pair{c.error().code, c.error().message};
    };
    const std::string index = "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>";
    BOOST_TEST(error("").second ==
               "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is "
               "empty");
    BOOST_TEST(error("<IndexDocument><Suffix>a/b.html</Suffix></IndexDocument>").second ==
               "The IndexDocument Suffix is not well formed");
    BOOST_TEST(error("<IndexDocument><Suffix></Suffix></IndexDocument>").first ==
               "InvalidArgument");
    BOOST_TEST(error(index + "<RedirectAllRequestsTo><HostName>x</HostName>"
                             "</RedirectAllRequestsTo>")
                   .first == "InvalidRequest");
    BOOST_TEST(
        error("<RedirectAllRequestsTo><Protocol>http</Protocol></RedirectAllRequestsTo>").first ==
        "MalformedXML");
    BOOST_TEST(error("<RedirectAllRequestsTo><HostName>x</HostName><Protocol>ftp</Protocol>"
                     "</RedirectAllRequestsTo>")
                   .first == "InvalidArgument");
    const auto rule = [&](const std::string& body) {
        return error(index + "<RoutingRules><RoutingRule>" + body +
                     "</RoutingRule></RoutingRules>");
    };
    BOOST_TEST(rule("<Redirect><HttpRedirectCode>300</HttpRedirectCode></Redirect>").second ==
               "The provided HTTP redirect code (300) is not valid. Valid codes are 3XX except "
               "300.");
    BOOST_TEST(rule("<Redirect><HttpRedirectCode>200</HttpRedirectCode></Redirect>").first ==
               "InvalidArgument");
    BOOST_TEST(rule("<Condition><HttpErrorCodeReturnedEquals>302</HttpErrorCodeReturnedEquals>"
                    "</Condition><Redirect><HostName>x</HostName></Redirect>")
                   .first == "InvalidArgument");
    BOOST_TEST(rule("<Redirect><ReplaceKeyWith>a</ReplaceKeyWith><ReplaceKeyPrefixWith>b"
                    "</ReplaceKeyPrefixWith></Redirect>")
                   .second == "You can only define ReplaceKeyPrefix or ReplaceKey but not both.");
    BOOST_TEST(rule("<Condition/><Redirect><HostName>x</HostName></Redirect>").first ==
               "InvalidRequest");
    BOOST_TEST(rule("<Redirect/>").first == "InvalidRequest");
    BOOST_TEST(rule("<Condition><KeyPrefixEquals>a</KeyPrefixEquals></Condition>").first ==
               "MalformedXML");
    BOOST_TEST(rule("<Redirect><Protocol>gopher</Protocol></Redirect>").first == "InvalidArgument");

    std::string many = index + "<RoutingRules>";
    for (int i = 0; i < 51; ++i) {
        many += "<RoutingRule><Redirect><HostName>x</HostName></Redirect></RoutingRule>";
    }
    BOOST_TEST(error(many + "</RoutingRules>").first == "InvalidRequest");
}

BOOST_AUTO_TEST_CASE(routing_rules_match_in_order_before_and_after_errors) {
    const auto c = s3::parse_website_configuration(website(R"(
      <IndexDocument><Suffix>index.html</Suffix></IndexDocument>
      <RoutingRules>
        <RoutingRule>
          <Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>
          <Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect>
        </RoutingRule>
        <RoutingRule>
          <Condition><KeyPrefixEquals>img/</KeyPrefixEquals>
            <HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>
          <Redirect><HostName>cdn.example.com</HostName><Protocol>https</Protocol>
            <HttpRedirectCode>307</HttpRedirectCode></Redirect>
        </RoutingRule>
        <RoutingRule>
          <Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>
          <Redirect><ReplaceKeyWith>not found.html</ReplaceKeyWith></Redirect>
        </RoutingRule>
      </RoutingRules>)"))
                       .value();
    const auto* docs = s3::match_routing_rule(c, "docs/a/b.html", std::nullopt);
    BOOST_REQUIRE(docs != nullptr);
    BOOST_TEST(s3::routing_location(*docs, "docs/a/b.html", "site.web.test", "http") ==
               "http://site.web.test/documents/a/b.html");
    // Error-code rules never match before the object is read.
    BOOST_TEST(s3::match_routing_rule(c, "img/x.png", std::nullopt) == nullptr);
    const auto* img = s3::match_routing_rule(c, "img/x.png", 404U);
    BOOST_REQUIRE(img != nullptr);
    BOOST_TEST(s3::routing_location(*img, "img/x.png", "site.web.test", "http") ==
               "https://cdn.example.com/img/x.png");
    BOOST_TEST(img->redirect.http_redirect_code.value() == 307U);
    const auto* other = s3::match_routing_rule(c, "page.html", 404U);
    BOOST_REQUIRE(other != nullptr);
    BOOST_TEST(s3::routing_location(*other, "page.html", "site.web.test:8080", "http") ==
               "http://site.web.test:8080/not%20found.html");
    BOOST_TEST(s3::match_routing_rule(c, "page.html", 403U) == nullptr);
}

BOOST_AUTO_TEST_CASE(website_error_pages_are_html) {
    auto e =
        kythira::aws_rest_xml::errors::make(404, "NoSuchKey", "The specified key does not exist.");
    e.extra.emplace_back("Key", "<script>.html");
    const auto page = s3::website_error_html(e, "REQ1");
    BOOST_TEST(contains(page, "<title>404 Not Found</title>"));
    BOOST_TEST(contains(page, "<li>Code: NoSuchKey</li>"));
    BOOST_TEST(contains(page, "<li>Key: &lt;script&gt;.html</li>"));
    BOOST_TEST(contains(page, "<li>RequestId: REQ1</li>"));
    BOOST_TEST(!contains(page, "Custom Error Document"));
    const auto with_doc = s3::website_error_html(
        e, "REQ1", kythira::aws_rest_xml::errors::make(403, "AccessDenied", "Access Denied"));
    BOOST_TEST(contains(with_doc,
                        "An Error Occurred While Attempting to Retrieve a Custom Error Document"));
    BOOST_TEST(contains(with_doc, "<li>Code: AccessDenied</li>"));
    BOOST_TEST(s3::website_path("a b/ü?.html") == "/a%20b/%C3%BC%3F.html");
}
