// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Item sealing (`.kiro/specs/kms-compatible-api/` task 16, Requirements
// 12.3, 12.4 and 12.10): a sealed value opens only under its table key and
// table id, is the same bytes on every replica, and is refused by a reader
// of the clear format; the item state machine seals what a sealed command
// writes (the item, its LSI entries, a GSI entry) and leaves the rest
// clear; a replica without the key fails the entry with nothing written
// and applies it once the key arrives; and the command format carries the
// flag only when set.

#define BOOST_TEST_MODULE dynamodb_item_sealing_test

#include <boost/test/unit_test.hpp>

#include <kythira/dynamodb/expr_request.hpp>
#include <kythira/dynamodb/item_sealing.hpp>
#include <kythira/dynamodb/item_state_machine.hpp>
#include <kythira/dynamodb/key_layout.hpp>

#include <raft/memory_kv_engine.hpp>

#include <boost/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ddb = kythira::dynamodb;
using kythira::column_family;
using kythira::memory_kv_engine;

namespace {

using item_sm = ddb::dynamo_item_state_machine<>;

constexpr std::uint64_t k_table = 7;
constexpr std::uint64_t k_index = 9;

auto key_of(unsigned char fill) -> ddb::table_key_bytes {
    ddb::table_key_bytes k{};
    k.fill(fill);
    return k;
}

auto schema() -> ddb::key_schema {
    ddb::key_schema s;
    s.partition_name = "pk";
    s.partition_type = ddb::attribute_type::S;
    s.sort_name = "sk";
    s.sort_type = ddb::attribute_type::N;
    return s;
}

auto json_item(const char* text) -> ddb::item {
    auto parsed = ddb::item_from_json(boost::json::parse(text).as_object());
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

auto bytes_of(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(s[i]);
    }
    return out;
}

auto put_command(const char* it, bool sealed) -> ddb::item_command {
    ddb::item_command c;
    c.op = ddb::item_command::kind::put;
    c.table_id = k_table;
    c.schema = schema();
    c.payload = json_item(it);
    c.sealed = sealed;
    return c;
}

/// One replica: an engine and an item group over every table, sealing
/// through `ring`.
struct replica {
    memory_kv_engine engine;
    item_sm sm;
    std::uint64_t index = 0;

    explicit replica(std::shared_ptr<ddb::table_key_ring> ring) {
        sm.set_sealer(ddb::item_sealer(std::move(ring)));
        sm.open(engine, ddb::prefix_range("t/"));
    }

    auto run(const ddb::item_command& c) -> ddb::item_result {
        const auto out = sm.apply(bytes_of(ddb::encode_item_command(c)), ++index);
        auto r = ddb::decode_item_result(
            std::string_view(reinterpret_cast<const char*>(out.data()), out.size()));
        BOOST_REQUIRE(r.has_value());
        return *r;
    }

    /// Every data value, by key, as stored.
    [[nodiscard]] auto stored() const -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> out;
        engine.scan(column_family::data, ddb::prefix_range("t/"), kythira::scan_direction::forward,
                    [&](std::string_view k, std::string_view v) {
                        out.emplace_back(std::string(k), std::string(v));
                        return true;
                    });
        return out;
    }

    auto get(const char* key) const -> std::optional<ddb::item> {
        return sm.get_item(k_table, schema(), json_item(key));
    }
};

auto ring_with(std::uint64_t id, const ddb::table_key_bytes& key)
    -> std::shared_ptr<ddb::table_key_ring> {
    auto ring = std::make_shared<ddb::table_key_ring>();
    const std::array<std::uint64_t, 1> ids{id};
    ring->put(ids, key);
    return ring;
}

constexpr const char* k_item = R"({"pk":{"S":"a"},"sk":{"N":"1"},"secret":{"S":"hunter2"}})";
constexpr const char* k_key = R"({"pk":{"S":"a"},"sk":{"N":"1"}})";

}  // namespace

BOOST_AUTO_TEST_CASE(a_sealed_value_opens_only_under_its_key_and_table) {
    const ddb::item_key key(key_of(1));
    const auto ikey = ddb::table_prefix(k_table) + "abc";
    const std::string clear = "\x01 the encoded item";
    const auto sealed = key.seal(k_table, ikey, clear);
    BOOST_TEST(ddb::is_sealed_value(sealed));
    BOOST_TEST(sealed.size() == clear.size() + 29U);
    BOOST_TEST(sealed.find("encoded item") == std::string::npos);
    BOOST_TEST(key.open(k_table, sealed) == clear);

    // The same inputs give the same bytes (every replica writes them);
    // another key, value or table gives another nonce.
    BOOST_TEST(key.seal(k_table, ikey, clear) == sealed);
    BOOST_TEST(key.seal(k_table, ikey + "d", clear).substr(1, 12) != sealed.substr(1, 12));
    BOOST_TEST(key.seal(k_table, ikey, clear + "!").substr(1, 12) != sealed.substr(1, 12));
    BOOST_TEST(key.seal(k_index, ikey, clear).substr(1, 12) != sealed.substr(1, 12));

    // Another table id, another table key, or a flipped byte: no.
    BOOST_CHECK_THROW((void)key.open(k_index, sealed), ddb::sealed_value_error);
    BOOST_CHECK_THROW((void)ddb::item_key(key_of(2)).open(k_table, sealed),
                      ddb::sealed_value_error);
    auto bent = sealed;
    bent[20] = static_cast<char>(bent[20] ^ 1);
    BOOST_CHECK_THROW((void)key.open(k_table, bent), ddb::sealed_value_error);
    BOOST_CHECK_THROW((void)key.open(k_table, sealed.substr(0, 20)), ddb::sealed_value_error);

    // An empty value seals too.
    BOOST_TEST(key.open(k_table, key.seal(k_table, ikey, "")).empty());

    // A reader of the clear format refuses a sealed value rather than
    // misreading it.
    const auto encoded = ddb::encode_item(json_item(k_item));
    BOOST_TEST(!ddb::decode_item(key.seal(k_table, ikey, encoded)).has_value());
}

BOOST_AUTO_TEST_CASE(the_ring_remembers_what_it_was_asked_for) {
    ddb::table_key_ring ring;
    BOOST_TEST(!ring.find(k_table));
    BOOST_CHECK_THROW((void)ring.require(k_index), ddb::table_key_unavailable);
    BOOST_TEST((ring.wanted() == std::set<std::uint64_t>{k_table, k_index}));

    const std::array<std::uint64_t, 2> ids{k_table, k_index};
    ring.put(ids, key_of(3));
    BOOST_TEST(ring.wanted().empty());
    BOOST_TEST(ring.holds(k_index));
    // One key for the table and its index.
    BOOST_TEST(ring.find(k_table) == ring.find(k_index));
    ring.erase(k_table);
    BOOST_TEST(!ring.holds(k_table));

    BOOST_TEST((ddb::key_table_id(ddb::table_prefix(k_index) + "x") == std::optional(k_index)));
    BOOST_TEST(!ddb::key_table_id("u/xxxxxxxx/").has_value());
    BOOST_TEST(!ddb::key_table_id("t/short").has_value());
}

BOOST_AUTO_TEST_CASE(a_sealer_passes_clear_values_and_needs_a_key_for_sealed_ones) {
    const ddb::item_sealer none;
    const auto ikey = ddb::table_prefix(k_table) + "k";
    BOOST_TEST(none.store(false, ikey, "clear") == "clear");
    BOOST_TEST(none.load(ikey, "\x01clear") == "\x01clear");
    BOOST_CHECK_THROW((void)none.store(true, ikey, "clear"), ddb::table_key_unavailable);

    const ddb::item_sealer with(ring_with(k_table, key_of(4)));
    const auto sealed = with.store(true, ikey, "\x01value");
    BOOST_TEST(with.load(ikey, sealed) == "\x01value");
    BOOST_CHECK_THROW((void)none.load(ikey, sealed), ddb::table_key_unavailable);
    BOOST_CHECK_THROW((void)with.store(true, "not an item key", "v"), std::logic_error);
}

BOOST_AUTO_TEST_CASE(a_sealed_put_is_stored_sealed_and_read_clear) {
    auto ring = ring_with(k_table, key_of(5));
    replica r(ring);
    BOOST_TEST((r.run(put_command(k_item, true)).outcome == ddb::item_result::status::ok));
    const auto values = r.stored();
    BOOST_REQUIRE(values.size() == 1U);
    BOOST_TEST(ddb::is_sealed_value(values[0].second));
    BOOST_TEST(values[0].second.find("hunter2") == std::string::npos);
    // The key stays in the clear: the engine orders by it.
    BOOST_TEST(values[0].first.find('a') != std::string::npos);
    BOOST_TEST(ddb::find_attribute(*r.get(k_key), "secret")->str == "hunter2");

    // A conditional update reads the sealed item in apply and writes it
    // back sealed.
    ddb::item_command u;
    u.op = ddb::item_command::kind::update;
    u.table_id = k_table;
    u.schema = schema();
    u.payload = json_item(k_key);
    u.sealed = true;
    ddb::request_keys keys;
    keys.table = schema();
    auto compiled = ddb::compile_request(
        "UpdateItem",
        boost::json::parse(R"({"UpdateExpression":"SET #s = :v","ConditionExpression":)"
                           R"("#s = :old","ExpressionAttributeNames":{"#s":"secret"},)"
                           R"("ExpressionAttributeValues":{":v":{"S":"swordfish"},)"
                           R"(":old":{"S":"hunter2"}}})")
            .as_object(),
        keys);
    BOOST_REQUIRE(compiled.has_value());
    u.expressions = *compiled;
    BOOST_TEST((r.run(u).outcome == ddb::item_result::status::ok));
    BOOST_TEST(ddb::find_attribute(*r.get(k_key), "secret")->str == "swordfish");
    BOOST_TEST(ddb::is_sealed_value(r.stored()[0].second));

    // A clear write of another item stays clear, and both read back.
    BOOST_TEST((r.run(put_command(R"({"pk":{"S":"b"},"sk":{"N":"2"}})", false)).outcome ==
                ddb::item_result::status::ok));
    std::size_t sealed = 0;
    for (const auto& [k, v] : r.stored()) {
        sealed += ddb::is_sealed_value(v) ? 1 : 0;
    }
    BOOST_TEST(sealed == 1U);
    std::size_t seen = 0;
    r.sm.scan_items(ddb::table_range(k_table), kythira::scan_direction::forward,
                    [&](std::string_view, const ddb::item&) {
                        ++seen;
                        return true;
                    });
    BOOST_TEST(seen == 2U);
}

BOOST_AUTO_TEST_CASE(replicas_write_the_same_sealed_bytes) {
    const auto key = key_of(6);
    replica a(ring_with(k_table, key));
    replica b(ring_with(k_table, key));
    for (const auto* it : {k_item, R"({"pk":{"S":"c"},"sk":{"N":"3"},"n":{"N":"42"}})"}) {
        (void)a.run(put_command(it, true));
        (void)b.run(put_command(it, true));
    }
    BOOST_TEST((a.stored() == b.stored()));
}

BOOST_AUTO_TEST_CASE(lsi_and_gsi_entries_are_sealed_with_the_item) {
    replica r(ring_with(k_table, key_of(7)));
    auto c = put_command(R"({"pk":{"S":"a"},"sk":{"N":"1"},"l":{"S":"lsi-value"}})", true);
    ddb::local_index lsi;
    lsi.name = "by-l";
    lsi.number = 1;
    lsi.sort_name = "l";
    lsi.sort_type = ddb::attribute_type::S;
    c.lsis = {lsi};
    BOOST_TEST((r.run(c).outcome == ddb::item_result::status::ok));
    const auto values = r.stored();
    BOOST_REQUIRE(values.size() == 2U);  // the item and its LSI entry
    for (const auto& [k, v] : values) {
        BOOST_TEST(ddb::is_sealed_value(v));
        BOOST_TEST(v.find("lsi-value") == std::string::npos);
    }

    // A GSI entry lives under the index's id, sealed under the same table
    // key held for that id.
    auto ring = std::make_shared<ddb::table_key_ring>();
    const std::array<std::uint64_t, 2> ids{k_table, k_index};
    ring->put(ids, key_of(7));
    replica g(ring);
    ddb::item_command put;
    put.op = ddb::item_command::kind::index_put;
    put.table_id = k_table;
    put.target = ddb::table_prefix(k_index) + "entry";
    put.version = 1;
    put.payload = json_item(R"({"pk":{"S":"a"},"g":{"S":"gsi-value"}})");
    put.sealed = true;
    BOOST_TEST((g.run(put).outcome == ddb::item_result::status::ok));
    const auto entries = g.stored();
    BOOST_REQUIRE(entries.size() == 1U);
    BOOST_TEST(ddb::is_sealed_value(entries[0].second));
    BOOST_TEST(ddb::item_key(key_of(7)).open(k_index, entries[0].second) ==
               ddb::encode_item(put.payload));
}

BOOST_AUTO_TEST_CASE(a_replica_without_the_key_writes_nothing_until_it_has_it) {
    auto ring = std::make_shared<ddb::table_key_ring>();
    replica r(ring);
    BOOST_CHECK_THROW((void)r.run(put_command(k_item, true)), ddb::table_key_unavailable);
    BOOST_TEST(r.sm.applied_index() == 0U);
    BOOST_TEST(r.stored().empty());
    BOOST_TEST(ring->wanted().contains(k_table));

    // The group retries the same entry once the key is on the node.
    const std::array<std::uint64_t, 1> ids{k_table};
    ring->put(ids, key_of(8));
    const auto out = r.sm.apply(bytes_of(ddb::encode_item_command(put_command(k_item, true))), 1);
    BOOST_TEST(!out.empty());
    BOOST_TEST(r.sm.applied_index() == 1U);
    BOOST_TEST(ddb::find_attribute(*r.get(k_key), "secret")->str == "hunter2");

    // A reader without the key cannot read the item.
    replica other(std::make_shared<ddb::table_key_ring>());
    other.engine.write(
        kythira::write_batch{}.put(column_family::data, r.stored()[0].first, r.stored()[0].second));
    BOOST_CHECK_THROW((void)other.get(k_key), ddb::table_key_unavailable);
}

BOOST_AUTO_TEST_CASE(the_command_format_carries_the_flag_only_when_set) {
    auto c = put_command(k_item, false);
    const auto clear = ddb::encode_item_command(c);
    BOOST_TEST(static_cast<int>(clear[0]) <= 4);
    c.sealed = true;
    const auto sealed = ddb::encode_item_command(c);
    BOOST_TEST(static_cast<int>(sealed[0]) == 5);
    ddb::item_command back;
    BOOST_REQUIRE((ddb::decode_item_command(sealed, back) == ddb::item_command_status::ok));
    BOOST_TEST(back.sealed);
    BOOST_TEST((back == c));
    BOOST_REQUIRE((ddb::decode_item_command(clear, back) == ddb::item_command_status::ok));
    BOOST_TEST(!back.sealed);

    // A flag this release does not know is refused.
    auto bad = sealed;
    bad.back() = '\x02';
    BOOST_TEST((ddb::decode_item_command(bad, back) == ddb::item_command_status::malformed));
}

BOOST_AUTO_TEST_CASE(a_reseal_seals_a_clear_value_and_changes_nothing_else) {
    replica r(ring_with(k_table, key_of(9)));
    BOOST_TEST((r.run(put_command(k_item, false)).outcome == ddb::item_result::status::ok));
    const auto before = r.stored();
    BOOST_REQUIRE(before.size() == 1U);
    BOOST_TEST(!ddb::is_sealed_value(before[0].second));
    const auto version = r.sm.item_version(k_table, schema(), json_item(k_key));

    ddb::item_command c;
    c.op = ddb::item_command::kind::reseal;
    c.table_id = k_table;
    c.target = before[0].first;
    // Always written sealed, flag or not.
    const auto encoded = ddb::encode_item_command(c);
    BOOST_TEST(static_cast<int>(encoded[0]) == 5);
    BOOST_TEST((ddb::command_key(c) == std::optional<std::string>(c.target)));
    BOOST_TEST((r.run(c).outcome == ddb::item_result::status::ok));
    const auto after = r.stored();
    BOOST_TEST(ddb::is_sealed_value(after[0].second));
    BOOST_TEST(r.sm.item_version(k_table, schema(), json_item(k_key)) == version);
    BOOST_TEST(ddb::find_attribute(*r.get(k_key), "secret")->str == "hunter2");

    // Again, or on a key with nothing: no change.
    BOOST_TEST((r.run(c).outcome == ddb::item_result::status::ok));
    BOOST_TEST((r.stored() == after));
    c.target = ddb::table_prefix(k_table) + "nothing here";
    BOOST_TEST((r.run(c).outcome == ddb::item_result::status::ok));
    BOOST_TEST((r.stored() == after));
}
