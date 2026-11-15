// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// RFC 7512 PKCS#11 URIs as Kythira's key consumers parse them
// (raft/pkcs11_uri.hpp; .kiro/specs/virtual-hsm/ task 12, Requirement 9.1),
// and the DER helpers of raft/pkcs11_module.hpp that need no module: every
// example URI of RFC 7512 section 3 that uses only standard attributes,
// round trips through to_string(), the refusals, the PIN from pin-value and
// pin-source, and ECDSA signatures converted to DER. The wrapper against
// real modules is services/hsm's hsm_pkcs11_module_test.

#define BOOST_TEST_MODULE pkcs11_uri_test
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_uri.hpp>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace p11 = kythira::pkcs11;

namespace {

auto bytes_of(std::initializer_list<int> v) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    for (const int b : v) {
        out.push_back(static_cast<std::uint8_t>(b));
    }
    return out;
}

auto refused(const std::string& text) -> bool {
    try {
        (void)p11::uri::parse(text);
    } catch (const p11::uri_error&) {
        return true;
    }
    return false;
}

auto round_trips(const p11::uri& u) -> bool {
    return p11::uri::parse(u.to_string(true)) == u;
}

}  // namespace

BOOST_AUTO_TEST_CASE(rfc7512_examples) {
    const auto empty = p11::uri::parse("pkcs11:");
    BOOST_TEST((empty == p11::uri{}));

    const auto pub = p11::uri::parse("pkcs11:object=my-pubkey;type=public");
    BOOST_TEST(*pub.object == "my-pubkey");
    BOOST_TEST((*pub.type == p11::object_type::public_key));

    const auto priv =
        p11::uri::parse("pkcs11:object=my-key;type=private?pin-source=file:/etc/token");
    BOOST_TEST((*priv.type == p11::object_type::private_key));
    BOOST_TEST(*priv.pin_source == "file:/etc/token");

    const auto cert = p11::uri::parse(
        "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;"
        "manufacturer=Snake%20Oil,%20Inc.;model=1.0;object=my-certificate;type=cert;"
        "id=%69%95%3E%5C%F4%BD%EC%91;serial=?pin-source=file:/etc/token_pin");
    BOOST_TEST(*cert.token == "The Software PKCS#11 Softtoken");
    BOOST_TEST(*cert.manufacturer == "Snake Oil, Inc.");
    BOOST_TEST(*cert.model == "1.0");
    BOOST_TEST((*cert.type == p11::object_type::certificate));
    BOOST_TEST(*cert.id == bytes_of({0x69, 0x95, 0x3E, 0x5C, 0xF4, 0xBD, 0xEC, 0x91}),
               boost::test_tools::per_element());
    BOOST_TEST(cert.serial.has_value());
    BOOST_TEST(cert.serial->empty());
    BOOST_TEST(round_trips(cert));

    BOOST_TEST(*p11::uri::parse("pkcs11:object=my-sign-key;type=private?module-name=mypkcs11")
                    .module_name == "mypkcs11");
    BOOST_TEST(
        *p11::uri::parse("pkcs11:object=my-sign-key;type=private?module-path=/mnt/libmypkcs11.so.1")
             .module_path == "/mnt/libmypkcs11.so.1");

    const auto with_pin = p11::uri::parse(
        "pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc."
        "?pin-value=the-pin");
    BOOST_TEST(*with_pin.pin_value == "the-pin");
    BOOST_TEST(*with_pin.pin() == "the-pin");

    BOOST_TEST(*p11::uri::parse("pkcs11:slot-description=Sun%20Metaslot").slot_description ==
               "Sun Metaslot");

    const auto lib = p11::uri::parse(
        "pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;"
        "library-description=Soft%20Token%20Library;library-version=1.23");
    BOOST_TEST(*lib.library_manufacturer == "Snake Oil, Inc.");
    BOOST_TEST(*lib.library_description == "Soft Token Library");
    BOOST_TEST((*lib.library_version == p11::version_number{1, 23}));

    const auto joe = p11::uri::parse(
        "pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;"
        "id=%01%02%03%Ba%dd%Ca%fe%04%05%06");
    BOOST_TEST(*joe.token == "My token% created by Joe");
    BOOST_TEST((*joe.library_version == p11::version_number{3, 0}));
    BOOST_TEST(*joe.id == bytes_of({1, 2, 3, 0xBA, 0xDD, 0xCA, 0xFE, 4, 5, 6}),
               boost::test_tools::per_element());

    BOOST_TEST(*p11::uri::parse("pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;"
                                "object=my-certificate;type=cert")
                    .token == "A name with a substring %;");
    BOOST_TEST(*p11::uri::parse("pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;"
                                "object=my-certificate;type=cert")
                    .token == "Name with a small A with acute: \xC3\xA1");

    // The scheme is case-insensitive (RFC 3986); slot-id is decimal.
    BOOST_TEST(*p11::uri::parse("PKCS11:slot-id=42").slot_id == 42UL);
    // Characters RFC 7512 leaves unencoded: '&' in the path, '/' and '?'
    // in the query.
    BOOST_TEST(*p11::uri::parse("pkcs11:object=a&b").object == "a&b");
    BOOST_TEST(*p11::uri::parse("pkcs11:?module-path=/a/b?c").module_path == "/a/b?c");
}

BOOST_AUTO_TEST_CASE(to_string_round_trips_and_hides_the_pin) {
    p11::uri u;
    u.library_manufacturer = "Kythira";
    u.library_description = "Kythira virtual HSM client";
    u.library_version = p11::version_number{1, 0};
    u.slot_id = 7;
    u.slot_description = "virtual HSM slot 7";
    u.token = "a;b=c&d e%";
    u.serial = "0000000000000007";
    u.object = "key/with?odd chars";
    u.type = p11::object_type::secret_key;
    u.id = bytes_of({0, 0xFF, 0x3B});
    u.pin_value = "p&in=1";
    u.module_path = "/usr/lib/lib with space.so";
    BOOST_TEST(round_trips(u));
    const auto text = u.to_string();
    BOOST_TEST(text.find("pin-value") == std::string::npos);
    BOOST_TEST(u.to_string(true).find("pin-value=p%26in%3D1") != std::string::npos);
    BOOST_TEST(text.starts_with("pkcs11:library-manufacturer=Kythira;"));
    BOOST_TEST(p11::uri{}.to_string() == "pkcs11:");
    for (const auto t :
         {p11::object_type::public_key, p11::object_type::private_key,
          p11::object_type::certificate, p11::object_type::secret_key, p11::object_type::data}) {
        p11::uri v;
        v.type = t;
        BOOST_TEST(round_trips(v));
    }
}

BOOST_AUTO_TEST_CASE(refusals) {
    BOOST_TEST(refused(""));
    BOOST_TEST(refused("pkcs12:token=a"));
    BOOST_TEST(refused("token=a"));
    BOOST_TEST(refused("pkcs11:token=a;token=b"));  // twice
    BOOST_TEST(refused("pkcs11:token"));            // no value
    BOOST_TEST(refused("pkcs11:=a"));               // no name
    BOOST_TEST(refused("pkcs11:token=a b"));        // space unencoded
    BOOST_TEST(refused("pkcs11:token=a/b"));        // '/' unencoded in the path
    BOOST_TEST(refused("pkcs11:token=%4"));         // truncated escape
    BOOST_TEST(refused("pkcs11:token=%zz"));        // not hex
    BOOST_TEST(refused("pkcs11:type=secret"));      // unknown type
    BOOST_TEST(refused("pkcs11:slot-id=-1"));
    BOOST_TEST(refused("pkcs11:slot-id=0x10"));
    BOOST_TEST(refused("pkcs11:library-version=256"));
    BOOST_TEST(refused("pkcs11:library-version=1.x"));
    BOOST_TEST(refused("pkcs11:x-vendor=1"));            // vendor attribute
    BOOST_TEST(refused("pkcs11:token=a;vendor-aaa=b"));  // unknown attribute
    BOOST_TEST(refused("pkcs11:?vendor-bbb=b"));
    BOOST_TEST(refused("pkcs11:?pin-value=a&pin-source=/b"));
    BOOST_TEST(refused("pkcs11:?pin-value=a&pin-value=b"));
    BOOST_TEST(refused("pkcs11:?module-path=/a&b"));  // '&' is the query's separator
}

BOOST_AUTO_TEST_CASE(pin_from_pin_source) {
    std::random_device rd;
    const auto path =
        std::filesystem::temp_directory_path() / ("kythira-pin-" + std::to_string(rd()));
    std::ofstream(path) << "s3cret\nsecond line\n";
    BOOST_TEST(*p11::uri::parse("pkcs11:?pin-source=" + path.string()).pin() == "s3cret");
    BOOST_TEST(*p11::uri::parse("pkcs11:?pin-source=file:" + path.string()).pin() == "s3cret");
    BOOST_TEST(*p11::uri::parse("pkcs11:?pin-source=file://" + path.string()).pin() == "s3cret");
    std::filesystem::remove(path);
    BOOST_TEST(!p11::uri::parse("pkcs11:token=a").pin().has_value());
    BOOST_CHECK_THROW((void)p11::uri::parse("pkcs11:?pin-source=" + path.string()).pin(),
                      p11::uri_error);
    BOOST_CHECK_THROW((void)p11::uri::parse("pkcs11:?pin-source=relative/pin").pin(),
                      p11::uri_error);
}

BOOST_AUTO_TEST_CASE(ecdsa_signatures_in_der) {
    // Short integers, no padding.
    BOOST_TEST(p11::ecdsa_der(bytes_of({0x01, 0x02})) ==
                   bytes_of({0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}),
               boost::test_tools::per_element());
    // Leading zeros dropped; a high bit gets a zero byte in front.
    BOOST_TEST(p11::ecdsa_der(bytes_of({0x00, 0x00, 0x7F, 0x00, 0x80, 0x01})) ==
                   bytes_of({0x30, 0x08, 0x02, 0x01, 0x7F, 0x02, 0x03, 0x00, 0x80, 0x01}),
               boost::test_tools::per_element());
    // Zero is one zero byte.
    BOOST_TEST(p11::ecdsa_der(bytes_of({0x00, 0x00})) ==
                   bytes_of({0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}),
               boost::test_tools::per_element());
    // P-384 sizes: 2 x 49 + 4 + 2 = 104 bytes at most, still short form.
    const std::vector<std::uint8_t> high(96, 0xFF);
    const auto der = p11::ecdsa_der(high);
    BOOST_TEST(der.size() == 104U);
    BOOST_TEST(der[1] == 102U);
    // An odd length is not r || s.
    BOOST_CHECK_THROW((void)p11::ecdsa_der(bytes_of({1, 2, 3})), p11::error);
    BOOST_CHECK_THROW((void)p11::ecdsa_der({}), p11::error);
}

BOOST_AUTO_TEST_CASE(rv_names) {
    BOOST_TEST(p11::rv_name(CKR_PIN_INCORRECT) == "CKR_PIN_INCORRECT");
    BOOST_TEST(p11::rv_name(0x80001234UL) == "CKR 0x80001234");
    const p11::error e("C_Login", CKR_PIN_INCORRECT);
    BOOST_TEST(e.rv() == CKR_PIN_INCORRECT);
    BOOST_TEST(std::string(e.what()) == "C_Login: CKR_PIN_INCORRECT");
}
