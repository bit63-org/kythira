// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file aws_rest_xml_protocol_test.cpp
/// @brief The REST-XML codec's service-independent pieces
///        (`aws_rest_xml_protocol.hpp`; .kiro/specs/s3-compatible-storage/
///        task 3, Requirements 4.1, 4.4 and 4.5): query strings, addressing
///        and bucket names, the router over a small table, the XML reader
///        (including what it must refuse), and the response helpers. S3's
///        own table is checked against recorded client traffic in
///        services/s3/tests/s3_routing_test.cpp.

#define BOOST_TEST_MODULE aws_rest_xml_protocol_test
#include <boost/test/unit_test.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <array>
#include <chrono>
#include <string>
#include <vector>

namespace {

namespace rx = kythira::aws_rest_xml;

const rx::addressing_config addressing{{"s3.example.com", "s3.us-east-1.example.com"}};

auto no_headers() -> rx::router::header_fn {
    return [](std::string_view) { return false; };
}

}  // namespace

// ---- query strings ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(query_decodes_and_treats_a_bare_key_like_an_empty_value) {
    auto q = rx::parse_query("uploads&prefix=a%2Fb+c&delimiter=%2F&&x=1=2");
    BOOST_REQUIRE(q.has_value());
    BOOST_TEST(q->has("uploads"));
    BOOST_TEST(*q->get("uploads") == "");
    BOOST_TEST(*q->get("prefix") == "a/b c");
    BOOST_TEST(*q->get("delimiter") == "/");
    BOOST_TEST(*q->get("x") == "1=2");
    BOOST_TEST(q->params().size() == 4U);
    auto e = rx::parse_query("uploads=");
    BOOST_TEST(*e->get("uploads") == "");
    BOOST_TEST(!rx::parse_query("a=%zz").has_value());
    BOOST_TEST(rx::parse_query("a=%2").error().code == "InvalidURI");
    BOOST_TEST(rx::parse_query("").value().empty());
}

// ---- addressing -------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bucket_names_follow_s3s_rules_for_new_buckets) {
    for (const auto* ok :
         {"abc", "my-bucket", "my.bucket.name", "a1b2c3", "123", "a-b.c-d", "xn-not-a-prefix"}) {
        BOOST_TEST(rx::valid_bucket_name(ok), ok);
    }
    BOOST_TEST(rx::valid_bucket_name(std::string(63, 'a')));
    for (const auto* bad :
         {"ab",          "My-Bucket", "my_bucket",  "-abc",           "abc-",
          ".abc",        "abc.",      "a..b",       "a.-b",           "a-.b",
          "192.168.5.4", "xn--abc",   "sthree-abc", "amzn-s3-demo-x", "abc-s3alias",
          "abc--ol-s3",  "abc.mrap",  "abc--x-s3",  "abc--table-s3",  "abc def"}) {
        BOOST_TEST(!rx::valid_bucket_name(bad), bad);
    }
    BOOST_TEST(!rx::valid_bucket_name(std::string(64, 'a')));
    // Four labels but not all digits is a name, not an address.
    BOOST_TEST(rx::valid_bucket_name("192.168.5.a"));
}

BOOST_AUTO_TEST_CASE(virtual_hosted_and_path_style_name_the_same_resource) {
    auto v = rx::parse_resource("photos.s3.example.com:8443", "/2024/a%20b+c.jpg", addressing);
    BOOST_REQUIRE(v.has_value());
    BOOST_TEST(v->bucket == "photos");
    BOOST_TEST(v->key == "2024/a b+c.jpg");  // '+' in a path is a '+'
    BOOST_TEST((v->style == rx::addressing_style::virtual_hosted));

    auto p = rx::parse_resource("s3.example.com", "/photos/2024/a%20b+c.jpg", addressing);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->bucket == "photos");
    BOOST_TEST(p->key == "2024/a b+c.jpg");
    BOOST_TEST((p->style == rx::addressing_style::path));

    // A dotted bucket, a second domain, a case-insensitive host and a
    // trailing root dot.
    auto d = rx::parse_resource("My.Logs.S3.US-EAST-1.example.com.", "/k", addressing);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->bucket == "my.logs");
    BOOST_TEST(d->key == "k");

    // An address or a name that is not under a domain is path style.
    for (const auto* host : {"127.0.0.1:9000", "[::1]:9000", "localhost", "example.org"}) {
        auto r = rx::parse_resource(host, "/photos/k", addressing);
        BOOST_REQUIRE(r.has_value());
        BOOST_TEST(r->bucket == "photos");
        BOOST_TEST((r->style == rx::addressing_style::path));
    }
}

BOOST_AUTO_TEST_CASE(resource_kinds_and_keys_with_odd_characters) {
    auto svc = rx::parse_resource("s3.example.com", "/", addressing);
    BOOST_TEST((rx::kind_of(*svc) == rx::path_kind::service));
    auto bucket = rx::parse_resource("s3.example.com", "/photos", addressing);
    BOOST_TEST((rx::kind_of(*bucket) == rx::path_kind::bucket));
    auto slash = rx::parse_resource("s3.example.com", "/photos/", addressing);
    BOOST_TEST((rx::kind_of(*slash) == rx::path_kind::bucket));
    auto vbucket = rx::parse_resource("photos.s3.example.com", "/", addressing);
    BOOST_TEST((rx::kind_of(*vbucket) == rx::path_kind::bucket));

    // Keys keep doubled slashes, leading slashes and UTF-8.
    auto k = rx::parse_resource("photos.s3.example.com", "//a//b/%E2%82%AC", addressing);
    BOOST_TEST(k->key == "/a//b/\xE2\x82\xAC");
    BOOST_TEST((rx::kind_of(*k) == rx::path_kind::object));
}

BOOST_AUTO_TEST_CASE(bad_buckets_keys_and_paths_get_s3s_errors) {
    BOOST_TEST(rx::parse_resource("s3.example.com", "/Bad_Bucket/k", addressing).error().code ==
               "InvalidBucketName");
    BOOST_TEST(rx::parse_resource("Bad_Bucket.s3.example.com", "/k", addressing).error().code ==
               "InvalidBucketName");
    auto e = rx::parse_resource("s3.example.com", "/ab/k", addressing).error();
    BOOST_TEST(e.status == 400U);
    BOOST_TEST(e.extra.at(0).first == "BucketName");
    BOOST_TEST(e.extra.at(0).second == "ab");
    BOOST_TEST(rx::parse_resource("s3.example.com", "/photos/%zz", addressing).error().code ==
               "InvalidURI");
    BOOST_TEST(rx::parse_resource("s3.example.com", "/photos/%C0%AF", addressing).error().code ==
               "InvalidURI");  // overlong UTF-8
    BOOST_TEST(rx::parse_resource("s3.example.com", "photos/k", addressing).error().code ==
               "InvalidURI");
    const std::string longest(rx::limits::max_key_bytes, 'k');
    BOOST_TEST(rx::parse_resource("s3.example.com", "/photos/" + longest, addressing).has_value());
    BOOST_TEST(
        rx::parse_resource("s3.example.com", "/photos/" + longest + "k", addressing).error().code ==
        "KeyTooLongError");
}

// ---- routing ----------------------------------------------------------------

namespace {

// A table shaped like S3's, small enough to reason about.
constexpr std::array<rx::route, 9> table{{
    {"ListThings", "GET", "/", "", "", false},
    {"PutThing", "PUT", "/{Bucket}/{Key+}", "", "", false},
    {"PutPart", "PUT", "/{Bucket}/{Key+}", "partNumber,uploadId", "", false},
    {"CopyThing", "PUT", "/{Bucket}/{Key+}", "", "x-amz-copy-source", false},
    {"StartUpload", "POST", "/{Bucket}/{Key+}?uploads", "", "", false},
    {"OldGetConfig", "GET", "/{Bucket}?config", "", "", true},
    {"GetConfig", "GET", "/{Bucket}?config", "", "", false},
    {"ListV2", "GET", "/{Bucket}?list-type=2&x-id=ListV2", "", "", false},
    {"ListV1", "GET", "/{Bucket}", "", "", false},
}};

auto match(const rx::router& r, std::string_view method, rx::path_kind kind,
           std::string_view raw_query, std::vector<std::string> headers = {}) -> std::string {
    auto q = rx::parse_query(raw_query);
    auto m = r.match(method, kind, *q, [&](std::string_view name) {
        for (const auto& h : headers) {
            if (rx::detail::iequals(h, name)) {
                return true;
            }
        }
        return false;
    });
    return m ? std::string((*m)->name) : "error:" + m.error().code;
}

}  // namespace

BOOST_AUTO_TEST_CASE(router_prefers_the_most_specific_match) {
    const rx::router r(table);
    using rx::path_kind;
    BOOST_TEST(match(r, "GET", path_kind::service, "") == "ListThings");
    BOOST_TEST(match(r, "PUT", path_kind::object, "") == "PutThing");
    BOOST_TEST(match(r, "PUT", path_kind::object, "partNumber=1&uploadId=u") == "PutPart");
    BOOST_TEST(match(r, "PUT", path_kind::object, "uploadId=u") == "PutThing");
    BOOST_TEST(match(r, "PUT", path_kind::object, "", {"X-AMZ-COPY-SOURCE"}) == "CopyThing");
    BOOST_TEST(match(r, "POST", path_kind::object, "uploads=") == "StartUpload");
    BOOST_TEST(match(r, "GET", path_kind::bucket, "config") == "GetConfig");
    BOOST_TEST(match(r, "GET", path_kind::bucket, "list-type=2") == "ListV2");
    BOOST_TEST(match(r, "GET", path_kind::bucket, "list-type=2&x-id=Whatever") == "ListV2");
    BOOST_TEST(match(r, "GET", path_kind::bucket, "prefix=a") == "ListV1");
}

BOOST_AUTO_TEST_CASE(router_refuses_methods_and_sub_resources_it_has_no_route_for) {
    const rx::router r(table);
    using rx::path_kind;
    BOOST_TEST(match(r, "DELETE", path_kind::object, "") == "error:MethodNotAllowed");
    BOOST_TEST(match(r, "POST", path_kind::object, "") == "error:MethodNotAllowed");
    BOOST_TEST(match(r, "PUT", path_kind::object, "uploads") == "error:MethodNotAllowed");
    BOOST_TEST(match(r, "GET", path_kind::bucket, "list-type=1") == "error:MethodNotAllowed");
    const auto e = r.match("DELETE", path_kind::object, {}, no_headers()).error();
    BOOST_TEST(e.status == 405U);
    BOOST_TEST(r.sub_resources().contains("uploads"));
    BOOST_TEST(r.sub_resources().contains("list-type"));
    BOOST_TEST(!r.sub_resources().contains("x-id"));
}

BOOST_AUTO_TEST_CASE(router_skips_unrouted_operations_and_rejects_unknown_paths) {
    const rx::router r(table, {"ListThings"});
    BOOST_TEST(match(r, "GET", rx::path_kind::service, "") == "error:MethodNotAllowed");
    constexpr std::array<rx::route, 1> odd{{{"Odd", "POST", "/Odd", "", "", false}}};
    BOOST_CHECK_THROW(rx::router{odd}, std::invalid_argument);
    BOOST_CHECK_NO_THROW(rx::router(odd, {"Odd"}));
}

// ---- XML reading ------------------------------------------------------------

BOOST_AUTO_TEST_CASE(xml_reads_s3_request_bodies) {
    const std::string body = R"(<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object><Key>a &amp; b &lt;c&gt; &#x20AC;&#65;</Key></Object>
  <Object><Key><![CDATA[x<y&z]]></Key><VersionId>v1</VersionId></Object>
  <Quiet>true</Quiet>
</Delete>)";
    auto doc = rx::parse_xml(body);
    BOOST_REQUIRE_MESSAGE(doc.has_value(), (doc ? "" : doc.error().extra.at(0).second));
    BOOST_TEST(doc->name == "Delete");
    BOOST_TEST(*doc->attribute("xmlns") == std::string(rx::s3_namespace));
    const auto objects = doc->children_named("Object");
    BOOST_REQUIRE(objects.size() == 2U);
    BOOST_TEST(*objects[0]->child_text("Key") ==
               "a & b <c> \xE2\x82\xAC"
               "A");
    BOOST_TEST(*objects[1]->child_text("Key") == "x<y&z");
    BOOST_TEST(*objects[1]->child_text("VersionId") == "v1");
    BOOST_TEST(*doc->child_text("Quiet") == "true");
    BOOST_TEST(doc->child("Missing") == nullptr);
}

BOOST_AUTO_TEST_CASE(xml_names_drop_prefixes_and_text_keeps_spaces) {
    auto doc = rx::parse_xml(
        "<s3:CompleteMultipartUpload xmlns:s3='urn:x'><s3:Part><s3:ETag>\"e1\"</s3:ETag>"
        "<s3:PartNumber>1</s3:PartNumber></s3:Part></s3:CompleteMultipartUpload>");
    BOOST_REQUIRE(doc.has_value());
    BOOST_TEST(doc->name == "CompleteMultipartUpload");
    BOOST_TEST(*doc->child("Part")->child_text("ETag") == "\"e1\"");
    auto spaced = rx::parse_xml("<K>  two  spaces  </K>");
    BOOST_TEST(spaced->text == "  two  spaces  ");
    // Line ends are normalised as XML requires; a character reference keeps
    // a carriage return.
    auto crlf = rx::parse_xml("<K>a\r\nb\rc&#13;</K>");
    BOOST_TEST(crlf->text == "a\nb\nc\r");
    auto empty = rx::parse_xml("<Empty/>");
    BOOST_TEST(empty->text.empty());
    auto bom = rx::parse_xml("\xEF\xBB\xBF<A>1</A>");
    BOOST_TEST(bom->text == "1");
}

BOOST_AUTO_TEST_CASE(xml_refuses_dtds_unknown_entities_and_malformed_documents) {
    const std::vector<std::string> bad{
        "",
        "not xml",
        "<A>",
        "<A></B>",
        "<A><B></A></B>",
        "<A>1</A><B>2</B>",
        "<A>1</A>trailing",
        R"(<!DOCTYPE A [<!ENTITY x SYSTEM "file:///etc/passwd">]><A>&x;</A>)",
        R"(<?xml version="1.0"?><!DOCTYPE A><A/>)",
        "<A><!DOCTYPE B></A>",
        "<A>&x;</A>",
        "<A>&amp</A>",
        "<A>&#0;</A>",
        "<A>&#xD800;</A>",
        "<A>&#x110000;</A>",
        "<A>&#1;</A>",
        "<A>\x01</A>",
        "<A>\xC0\xAF</A>",
        "<A b='1' b='2'/>",
        "<A b=1/>",
        "<A b='<'/>",
        "<A b='1'c='2'/>",
        "<A><![CDATA[x</A>",
        "<A><!-- x</A>",
    };
    for (const auto& doc : bad) {
        auto r = rx::parse_xml(doc);
        BOOST_TEST(!r.has_value(), "accepted: " << doc);
        if (!r) {
            BOOST_TEST(r.error().code == "MalformedXML");
            BOOST_TEST(r.error().status == 400U);
        }
    }
}

BOOST_AUTO_TEST_CASE(xml_bounds_depth_and_element_count) {
    std::string deep;
    for (int i = 0; i < 40; ++i) {
        deep += "<a>";
    }
    for (int i = 0; i < 40; ++i) {
        deep += "</a>";
    }
    BOOST_TEST(!rx::parse_xml(deep).has_value());
    BOOST_TEST(rx::parse_xml(deep, {.max_depth = 40, .max_elements = 100}).has_value());

    std::string wide = "<r>";
    for (int i = 0; i < 1000; ++i) {
        wide += "<o/>";
    }
    wide += "</r>";
    BOOST_TEST(rx::parse_xml(wide).has_value());
    BOOST_TEST(!rx::parse_xml(wide, {.max_depth = 32, .max_elements = 500}).has_value());
}

// ---- responses --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(documents_carry_the_namespace_and_errors_do_not) {
    auto w = rx::document("ListAllMyBucketsResult");
    w.open("Buckets").open("Bucket").element("Name", "a&b").close().close().close();
    BOOST_TEST(w.str() ==
               R"(<?xml version="1.0" encoding="UTF-8"?>)"
               R"(<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">)"
               "<Buckets><Bucket><Name>a&amp;b</Name></Bucket></Buckets></ListAllMyBucketsResult>");

    auto e = rx::errors::invalid_bucket_name("Bad");
    BOOST_TEST(rx::error_xml(e, "REQ1", "HOST1") ==
               R"(<?xml version="1.0" encoding="UTF-8"?>)"
               "<Error><Code>InvalidBucketName</Code><Message>The specified bucket is not "
               "valid.</Message><BucketName>Bad</BucketName><RequestId>REQ1</RequestId>"
               "<HostId>HOST1</HostId></Error>");
    BOOST_TEST(rx::error_xml(rx::errors::method_not_allowed(), "R").find("<HostId>") ==
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(timestamps_in_both_s3_formats) {
    using namespace std::chrono;
    // 2009-10-12T17:50:30.123Z
    const sys_time<milliseconds> t{milliseconds{1255369830123}};
    BOOST_TEST(rx::iso8601_ms(t) == "2009-10-12T17:50:30.123Z");
    BOOST_TEST(rx::http_date(t) == "Mon, 12 Oct 2009 17:50:30 GMT");
    const sys_time<milliseconds> epoch{milliseconds{0}};
    BOOST_TEST(rx::iso8601_ms(epoch) == "1970-01-01T00:00:00.000Z");
    BOOST_TEST(rx::http_date(epoch) == "Thu, 01 Jan 1970 00:00:00 GMT");
}

BOOST_AUTO_TEST_CASE(keys_for_encoding_type_url) {
    BOOST_TEST(rx::url_encode_key("photos/2006/a b+c.jpg") == "photos/2006/a+b%2Bc.jpg");
    BOOST_TEST(rx::url_encode_key("x\x01y") == "x%01y");
    BOOST_TEST(rx::url_encode_key("\xE2\x82\xAC~-._") == "%E2%82%AC~-._");
    // What botocore's unquote_plus gives back.
    BOOST_TEST(*rx::percent_decode(rx::url_encode_key("a b+c/\xE2\x82\xAC"), true) ==
               "a b+c/\xE2\x82\xAC");
}

BOOST_AUTO_TEST_CASE(utf8_validation) {
    BOOST_TEST(rx::valid_utf8("plain"));
    BOOST_TEST(rx::valid_utf8("\xE2\x82\xAC\xF0\x9F\x98\x80"));
    BOOST_TEST(!rx::valid_utf8("\xC0\xAF"));          // overlong
    BOOST_TEST(!rx::valid_utf8("\xED\xA0\x80"));      // surrogate
    BOOST_TEST(!rx::valid_utf8("\xF4\x90\x80\x80"));  // above U+10FFFF
    BOOST_TEST(!rx::valid_utf8("\xE2\x82"));          // truncated
}
