// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file process_init.hpp
/// @brief `kythira::process_init`: the once-per-process setup a daemon's
///        `main()` does before its first future, whatever the backend.
///
/// With Folly linked, that is `folly::Init`: it registers the process-wide
/// singletons (the Timekeeper above all, which `tcp_rpc_client`'s retries and
/// every Folly-backed `kythira::Future` timeout use; without it the first
/// such timeout aborts with "Singleton folly::Timekeeper requested before
/// registrationComplete()"). In a build without Folly there is no Folly state
/// to set up, and the Boost and stdexec backends need nothing beforehand, so
/// it does nothing.
///
/// **Folly is detected by header, not by future backend.** Every CMake build
/// that finds Folly links it into `network_simulator`, whichever backend is
/// the default, and Folly-only pieces (executors, the proxygen transport)
/// can still reach its singletons there; so a Boost-backend build with Folly
/// installed still initialises it. Only a build whose prefix has no Folly at
/// all, the no-folly CI job's, compiles the no-op. Guarding on
/// `KYTHIRA_FUTURE_BACKEND_*` instead would skip `folly::Init` in a Folly
/// build that defines none of them (the Folly default defines no macro).
///
/// **Folly is given only the program name.** `folly::Init` hands its argv to
/// gflags, which rejects every flag it does not know, and every daemon parses
/// its own flags (or reads its settings from the environment) instead. So
/// the daemon's argv never reaches Folly, and the shim takes no argc/argv.
///
/// Construct it once, early in `main()`, after any signal mask that Folly's
/// threads should inherit, and keep it alive until `main()` returns.

#if __has_include(<folly/init/Init.h>)
#include <folly/init/Init.h>
#define KYTHIRA_PROCESS_INIT_HAS_FOLLY 1
#endif

#include <array>

namespace kythira {

class process_init {
public:
#if defined(KYTHIRA_PROCESS_INIT_HAS_FOLLY)
    // removeFlags=false: there are none to remove from a one-element argv.
    explicit process_init(char* program_name)
        : _argv_storage{program_name, nullptr}, _folly(&_argc, &_argv, false) {}
#else
    explicit process_init([[maybe_unused]] char* program_name) {}
#endif

    process_init(const process_init&) = delete;
    auto operator=(const process_init&) -> process_init& = delete;
    process_init(process_init&&) = delete;
    auto operator=(process_init&&) -> process_init& = delete;
    ~process_init() = default;

private:
#if defined(KYTHIRA_PROCESS_INIT_HAS_FOLLY)
    // folly::Init may keep pointers into argv, so the storage lives as long
    // as Folly. Declaration order is construction order: argc and argv are
    // set before _folly reads them.
    int _argc = 1;
    std::array<char*, 2> _argv_storage;
    char** _argv = _argv_storage.data();
    folly::Init _folly;
#endif
};

}  // namespace kythira
