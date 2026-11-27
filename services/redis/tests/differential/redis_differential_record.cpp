// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_differential_record.cpp
/// @brief Records what a Redis-compatible server answers to the
///        differential suite's seeded streams (.kiro/specs/
///        redis-general-data-types/ Requirement 25.1).
///
/// The real-cloud bundle (services/redis/aws-interop/) runs this inside the
/// VPC against ElastiCache Serverless (Valkey and Redis OSS engines) and
/// MemoryDB, and the files it writes are committed under
/// services/redis/tests/differential/recs/aws/, where the replay test plays
/// them against the gateway with no AWS account. Each stream is sent once in
/// RESP2 and once in RESP3, from an empty key space, one command at a time.
///
/// Keys carry a hash tag, `{s<seed>}`, so every key of a stream is in one
/// cluster slot: both services are always clustered and refuse a multi-key
/// command across slots. A `MOVED` or `ASK` reply stops the run, since it
/// means the endpoint is not a single-slot proxy and the recording would be
/// of the cluster's routing, not of the commands.
///
/// Usage:
///
///     redis_differential_record --server <name> --host <host> --port <port>
///         [--tls [--ca-file <pem>]] [--user <user>] [--password-env <VAR>] [--version <v>]
///         [--seeds "1 2 3"] [--length 600] --out <dir>
///
/// `--server` is the name the recording carries (`elasticache-valkey`,
/// `elasticache-redis`, `memorydb`). The secret, a password or an IAM auth
/// token, is read from the environment variable `--password-env` names so it
/// never appears on a command line. `--version` overrides what `HELLO`
/// reports (ElastiCache Serverless reports its proxy's version, so the
/// bundle passes the engine version the service describes). `--ca-file`
/// replaces the system CA store (for a local check against a server with a
/// private CA).

#include "redis_differential.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace diff = kythira::redis_diff;
namespace asio = boost::asio;

namespace {

/// One RESP connection, plaintext or TLS (with the system's CA store and
/// the host name checked).
class connection {
public:
    connection(const std::string& host, const std::string& port, bool tls,
               const std::string& ca_file)
        : _ssl_ctx(asio::ssl::context::tls_client), _tcp(_io) {
        asio::ip::tcp::resolver resolver(_io);
        const auto endpoints = resolver.resolve(host, port);
        if (tls) {
            if (ca_file.empty()) {
                _ssl_ctx.set_default_verify_paths();
            } else {
                _ssl_ctx.load_verify_file(ca_file);
            }
            _tls = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(_io, _ssl_ctx);
            _tls->set_verify_mode(asio::ssl::verify_peer);
            _tls->set_verify_callback(asio::ssl::host_name_verification(host));
            if (SSL_set_tlsext_host_name(_tls->native_handle(), host.c_str()) != 1) {
                throw std::runtime_error("cannot set SNI host name");
            }
            asio::connect(_tls->lowest_layer(), endpoints);
            _tls->handshake(asio::ssl::stream_base::client);
        } else {
            asio::connect(_tcp, endpoints);
        }
    }

    auto call_raw(const std::vector<std::string>& argv) -> std::string {
        const auto out = diff::encode_command(argv);
        if (_tls) {
            asio::write(*_tls, asio::buffer(out));
        } else {
            asio::write(_tcp, asio::buffer(out));
        }
        for (;;) {
            std::size_t pos = 0;
            if (diff::parse_reply(_buffer, pos)) {
                auto raw = _buffer.substr(0, pos);
                _buffer.erase(0, pos);
                return raw;
            }
            std::array<char, 65536> chunk{};
            const auto n =
                _tls ? _tls->read_some(asio::buffer(chunk)) : _tcp.read_some(asio::buffer(chunk));
            _buffer.append(chunk.data(), n);
        }
    }

private:
    asio::io_context _io;
    asio::ssl::context _ssl_ctx;
    asio::ip::tcp::socket _tcp;
    std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> _tls;
    std::string _buffer;
};

auto today() -> std::string {
    const auto t = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    std::array<char, 16> buf{};
    std::strftime(buf.data(), buf.size(), "%Y-%m-%d", &tm);
    return buf.data();
}

struct options {
    std::string server;
    std::string host;
    std::string port = "6379";
    bool tls = false;
    std::string ca_file;
    std::string user;
    std::string password;
    std::string version;
    std::vector<std::uint64_t> seeds{1, 2, 3};
    std::size_t length = 600;
    std::filesystem::path out;
};

auto parse_options(int argc, char** argv) -> options {
    options o;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(a + " needs a value");
            }
            return argv[++i];
        };
        if (a == "--server") {
            o.server = value();
        } else if (a == "--host") {
            o.host = value();
        } else if (a == "--port") {
            o.port = value();
        } else if (a == "--tls") {
            o.tls = true;
        } else if (a == "--ca-file") {
            o.ca_file = value();
        } else if (a == "--user") {
            o.user = value();
        } else if (a == "--password-env") {
            const auto name = value();
            const char* v = std::getenv(name.c_str());
            if (v == nullptr) {
                throw std::runtime_error("environment variable " + name + " is not set");
            }
            o.password = v;
        } else if (a == "--version") {
            o.version = value();
        } else if (a == "--seeds") {
            o.seeds.clear();
            std::istringstream in(value());
            for (std::uint64_t s = 0; in >> s;) {
                o.seeds.push_back(s);
            }
        } else if (a == "--length") {
            o.length = std::stoull(value());
        } else if (a == "--out") {
            o.out = value();
        } else {
            throw std::runtime_error("unknown option " + a);
        }
    }
    if (o.server.empty() || o.host.empty() || o.out.empty()) {
        throw std::runtime_error("--server, --host and --out are required");
    }
    return o;
}

/// `HELLO <protocol>` with credentials when there are any; the reply, or an
/// error reply when the server refuses the protocol.
auto hello(connection& c, const options& o, int protocol) -> diff::reply {
    std::vector<std::string> argv{"HELLO", std::to_string(protocol)};
    if (!o.password.empty()) {
        argv.insert(argv.end(), {"AUTH", o.user.empty() ? "default" : o.user, o.password});
    }
    return diff::parse_one(c.call_raw(argv));
}

auto reported_version(const diff::reply& hello_reply) -> std::string {
    const auto& items = hello_reply.items;
    for (std::size_t i = 0; i + 1 < items.size(); i += 2) {
        if (items[i].text == "version") {
            return items[i + 1].text;
        }
    }
    return {};
}

auto record_seed(const options& o, std::uint64_t seed) -> diff::recording {
    diff::generator_options opt;
    opt.length = o.length;
    opt.tag = "{s" + std::to_string(seed) + "}";
    const auto stream = diff::generate(seed, opt);

    diff::recording rec;
    rec.server = o.server;
    rec.version = o.version;
    rec.date = today();
    rec.seed = seed;
    rec.length = o.length;
    rec.tag = opt.tag;
    for (const auto& c : stream) {
        rec.entries.push_back({c.argv, c.shape, {}, {}});
    }

    for (const int protocol : {2, 3}) {
        connection c(o.host, o.port, o.tls, o.ca_file);
        const auto h = hello(c, o, protocol);
        if (h.kind == diff::reply_kind::error) {
            if (protocol == 3) {
                std::cerr << o.server << " refused HELLO 3 (" << h.text
                          << "); recording RESP2 only\n";
                continue;
            }
            throw std::runtime_error("HELLO 2 refused: " + h.text);
        }
        if (rec.version.empty()) {
            rec.version = reported_version(h);
        }
        for (const auto& k : diff::stream_keys(opt)) {
            const auto r = diff::parse_one(c.call_raw({"DEL", k}));
            if (r.kind == diff::reply_kind::error) {
                throw std::runtime_error("DEL " + k + ": " + r.text);
            }
        }
        for (auto& e : rec.entries) {
            auto raw = c.call_raw(e.argv);
            const auto r = diff::parse_one(raw);
            if (r.kind == diff::reply_kind::error &&
                (r.text.starts_with("MOVED") || r.text.starts_with("ASK"))) {
                throw std::runtime_error("redirected (" + r.text +
                                         "): the endpoint is not a single-slot proxy");
            }
            (protocol == 2 ? e.resp2 : e.resp3) = std::move(raw);
        }
    }
    return rec;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    try {
        const auto o = parse_options(argc, argv);
        std::filesystem::create_directories(o.out);
        for (const auto seed : o.seeds) {
            const auto rec = record_seed(o, seed);
            const auto path = o.out / (o.server + "-seed" + std::to_string(seed) + ".json");
            std::ofstream(path) << diff::serialize(rec);
            std::cout << "wrote " << path.string() << " (" << rec.server << " " << rec.version
                      << ", " << rec.entries.size() << " commands)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "redis_differential_record: " << e.what() << "\n";
        return 1;
    }
}
