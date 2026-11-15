// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm_ctl: the operator's command line for the virtual HSM
// (.kiro/specs/virtual-hsm/ task 7). Each command is one request to a
// node's operator API over mutual TLS, with the operator's certificate.
//
//   hsm_ctl [options] status
//   hsm_ctl [options] init --k K --n N [--mode operator|node]
//   hsm_ctl [options] unseal [SHARE | -]      (- or nothing: read stdin)
//   hsm_ctl [options] unseal --reset
//   hsm_ctl [options] seal
//   hsm_ctl [options] rekey [--k K] [--n N] [--mode operator|node]
//
// Options (each also read from the environment):
//   --url URL     HSM_CTL_URL    a node's API, https://host:port
//   --cert FILE   HSM_CTL_CERT   the operator's certificate chain
//   --key FILE    HSM_CTL_KEY    and key
//   --ca FILE     HSM_CTL_CA     the CA the node's certificate chains to
//   --timeout S   HSM_CTL_TIMEOUT_S  the whole request (30)
//   --insecure-plaintext         plain HTTP (test clusters only)
//
// The answer is printed as JSON on stdout; the exit status is 0 for a 2xx
// answer, 1 for any other answer and 2 for a usage or connection error.
// init and rekey print each share once and nothing keeps them: hand each
// to its holder and do not store them together.

#include <kythira/hsm/mtls_client.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view usage = R"(usage: hsm_ctl [options] COMMAND

commands:
  status                              this node's state
  init --k K --n N [--mode operator|node]
                                      generate the master key and print its
                                      n shares, once
  unseal [SHARE | -]                  enter one share on this node (- or no
                                      share: read it from stdin)
  unseal --reset                      discard the shares entered on this node
  seal                                every node discards its keys
  rekey [--k K] [--n N] [--mode operator|node]
                                      a new master key and new shares; the
                                      old shares stop working

options (environment):
  --url URL        (HSM_CTL_URL)        a node's API, https://host:port
  --cert FILE      (HSM_CTL_CERT)       the operator's certificate chain
  --key FILE       (HSM_CTL_KEY)        the operator's key
  --ca FILE        (HSM_CTL_CA)         the CA the node's certificate chains to
  --timeout S      (HSM_CTL_TIMEOUT_S)  seconds for the whole request (30)
  --insecure-plaintext                  plain HTTP, for test clusters only
)";

struct usage_error : std::exception {
    std::string message;
    explicit usage_error(std::string m) : message(std::move(m)) {}
    [[nodiscard]] auto what() const noexcept -> const char* override { return message.c_str(); }
};

auto env_or(const char* name, std::string fallback = {}) -> std::string {
    const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): single-threaded CLI
    return v != nullptr ? std::string(v) : fallback;
}

struct invocation {
    kythira::hsm::peer_client_config tls;
    std::string url;
    std::string command;
    std::vector<std::string> args;
    std::map<std::string, std::string> flags;
};

auto parse(int argc, char** argv) -> invocation {
    invocation inv;
    inv.url = env_or("HSM_CTL_URL");
    inv.tls.cert_path = env_or("HSM_CTL_CERT");
    inv.tls.key_path = env_or("HSM_CTL_KEY");
    inv.tls.ca_path = env_or("HSM_CTL_CA");
    std::string timeout = env_or("HSM_CTL_TIMEOUT_S", "30");
    const std::vector<std::string> words(argv + 1, argv + argc);
    for (std::size_t i = 0; i < words.size(); ++i) {
        const auto& w = words[i];
        const auto value = [&]() -> std::string {
            if (i + 1 >= words.size()) {
                throw usage_error(w + " needs a value");
            }
            return words[++i];
        };
        if (w == "--help" || w == "-h") {
            inv.command = "help";
            return inv;
        }
        if (w == "--url") {
            inv.url = value();
        } else if (w == "--cert") {
            inv.tls.cert_path = value();
        } else if (w == "--key") {
            inv.tls.key_path = value();
        } else if (w == "--ca") {
            inv.tls.ca_path = value();
        } else if (w == "--timeout") {
            timeout = value();
        } else if (w == "--insecure-plaintext") {
            inv.tls.plaintext = true;
        } else if (w == "--k" || w == "--n" || w == "--mode") {
            inv.flags[w.substr(2)] = value();
        } else if (w == "--reset") {
            inv.flags["reset"] = "true";
        } else if (w.starts_with("--")) {
            throw usage_error("unknown option " + w);
        } else if (inv.command.empty()) {
            inv.command = w;
        } else {
            inv.args.push_back(w);
        }
    }
    try {
        inv.tls.timeout = std::chrono::seconds{std::stoul(timeout)};
    } catch (const std::exception&) {
        throw usage_error("the timeout is a number of seconds");
    }
    if (inv.command.empty()) {
        throw usage_error("no command");
    }
    if (inv.url.empty()) {
        throw usage_error("no --url (or HSM_CTL_URL)");
    }
    return inv;
}

auto split_body(const invocation& inv) -> std::string {
    boost::json::object o;
    for (const char* name : {"k", "n"}) {
        if (const auto it = inv.flags.find(name); it != inv.flags.end()) {
            try {
                o[name] = std::stoi(it->second);
            } catch (const std::exception&) {
                throw usage_error(std::string("--") + name + " is a number");
            }
        }
    }
    if (const auto it = inv.flags.find("mode"); it != inv.flags.end()) {
        o["mode"] = it->second;
    }
    return boost::json::serialize(o);
}

auto read_share(const invocation& inv) -> std::string {
    if (!inv.args.empty() && inv.args[0] != "-") {
        return inv.args[0];
    }
    std::string share;
    std::getline(std::cin, share);
    return share;
}

/// The request a command makes: method, path and body.
struct call {
    std::string method;
    std::string path;
    std::string body;
};

auto call_of(const invocation& inv) -> call {
    const auto& c = inv.command;
    if (c == "status") {
        return {"GET", "/v1/status", {}};
    }
    if (c == "init") {
        if (!inv.flags.contains("k") || !inv.flags.contains("n")) {
            throw usage_error("init needs --k and --n");
        }
        return {"POST", "/v1/init", split_body(inv)};
    }
    if (c == "unseal") {
        if (inv.flags.contains("reset")) {
            return {"DELETE", "/v1/unseal", {}};
        }
        return {"POST", "/v1/unseal",
                boost::json::serialize(boost::json::object{{"share", read_share(inv)}})};
    }
    if (c == "seal") {
        return {"POST", "/v1/seal", {}};
    }
    if (c == "rekey") {
        return {"POST", "/v1/rekey", split_body(inv)};
    }
    throw usage_error("unknown command " + c);
}

/// Shares one per line on stdout, with what to do with them on stderr,
/// then the rest of the answer.
void print_answer(const std::string& body) {
    boost::json::value v;
    try {
        v = boost::json::parse(body);
    } catch (const std::exception&) {
        std::cout << body << "\n";
        return;
    }
    if (v.is_object() && v.as_object().contains("shares")) {
        auto& o = v.as_object();
        std::cerr << "Each share is printed once and kept nowhere. Hand each to its holder;\n"
                     "any "
                  << o.at("k") << " of them rebuild the master key.\n";
        for (const auto& share : o.at("shares").as_array()) {
            std::cout << std::string_view(share.as_string()) << "\n";
        }
        o.erase("shares");
    }
    std::cout << boost::json::serialize(v) << "\n";
}

}  // namespace

auto main(int argc, char** argv) -> int {
    try {
        const auto inv = parse(argc, argv);
        if (inv.command == "help") {
            std::cout << usage;
            return 0;
        }
        const auto c = call_of(inv);
        const kythira::hsm::mtls_client client(inv.tls);
        const auto res =
            client.request(c.method, inv.url, c.path, c.body, "application/json", "hsm_ctl");
        if (!res) {
            std::cerr << "hsm_ctl: no answer from " << inv.url
                      << " (connection, TLS handshake or timeout)\n";
            return 2;
        }
        print_answer(res->second);
        return res->first >= 200 && res->first < 300 ? 0 : 1;
    } catch (const usage_error& e) {
        std::cerr << "hsm_ctl: " << e.what() << "\n\n" << usage;
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "hsm_ctl: " << e.what() << "\n";
        return 2;
    }
}
