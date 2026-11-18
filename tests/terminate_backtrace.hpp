// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file
/// Names the throw site when a test process dies of std::terminate.
///
/// An exception that escapes a thread's function or a noexcept function
/// ends the process through std::terminate, and all a CI log then shows is
/// "terminate called after throwing an instance of 'std::system_error'
/// what(): Invalid argument" and Boost.Test's report of the SIGABRT that
/// follows. Which thread threw, and from where, is lost with the process.
///
/// The runtime calls the terminate handler from the throwing thread while
/// the throw site is still on its stack (the search for a handler fails
/// before anything unwinds), so a handler that walks its own stack names
/// it. Including this header installs one that prints the exception, the
/// raw frames, and the frames of the test binary itself resolved through
/// addr2line when that is installed, then aborts as before. It changes
/// nothing for a process that does not terminate.

#include <cxxabi.h>
#include <execinfo.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <typeinfo>

namespace kythira::testing {

/// The std::terminate handler `terminate_backtrace_installed` installs.
[[noreturn]] inline void print_terminate_backtrace() {
    std::array<void*, 64> frames{};
    const int depth = ::backtrace(frames.data(), static_cast<int>(frames.size()));

    std::cerr << "\nstd::terminate called";
    if (const std::type_info* type = abi::__cxa_current_exception_type(); type != nullptr) {
        int status = 0;
        const std::unique_ptr<char, decltype(&std::free)> name(
            abi::__cxa_demangle(type->name(), nullptr, nullptr, &status), &std::free);
        std::cerr << " with an active " << (status == 0 && name ? name.get() : type->name());
        try {
            throw;
        } catch (const std::exception& e) {
            std::cerr << ": " << e.what();
        } catch (...) {  // NOLINT(bugprone-empty-catch): diagnostics only
        }
    }
    std::cerr << "; backtrace of the terminating thread:\n" << std::flush;
    ::backtrace_symbols_fd(frames.data(), depth, STDERR_FILENO);

    // backtrace_symbols names only exported symbols; a frame in the test
    // binary itself usually reads "<path>(+0x1234)". addr2line turns those
    // offsets into function, file and line.
    const std::unique_ptr<char*, decltype(&std::free)> symbols(
        ::backtrace_symbols(frames.data(), depth), &std::free);
    if (symbols) {
        std::string offsets;
        for (int i = 0; i < depth; ++i) {
            const std::string s(symbols.get()[i]);  // NOLINT: C array from glibc
            const auto open = s.find("(+0x");
            const auto close = s.find(')', open);
            // Shared libraries' offsets mean nothing against the binary.
            if (open != std::string::npos && close != std::string::npos &&
                s.rfind(".so", open) == std::string::npos) {
                offsets += ' ' + s.substr(open + 2, close - open - 2);
            }
        }
        if (!offsets.empty()) {
            const std::string cmd =
                "command -v addr2line >/dev/null 2>&1 && addr2line -f -C -p -e "
                "/proc/" +
                std::to_string(::getpid()) + "/exe" + offsets + " 1>&2";
            std::cerr << "resolved through addr2line:\n" << std::flush;
            (void)std::system(cmd.c_str());  // NOLINT(cert-env33-c): diagnostics only
        }
    }
    std::cerr << std::flush;
    std::abort();
}

/// Installs print_terminate_backtrace() once per test binary, before main().
inline const bool terminate_backtrace_installed =
    (std::set_terminate(&print_terminate_backtrace), true);

}  // namespace kythira::testing
