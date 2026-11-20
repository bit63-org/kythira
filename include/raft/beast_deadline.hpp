// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file beast_deadline.hpp
/// @brief Blocking Beast calls that keep a stream's deadline.
///
/// `beast::tcp_stream::expires_after()` bounds asynchronous operations
/// only: a synchronous `connect`, TLS `handshake`, `http::write` or
/// `http::read` ignores it and waits as long as the kernel lets it. A dial
/// to an address nothing answers any more (a container restarted at a new
/// address under rootless Podman, its name not yet updated) waits out the
/// kernel's SYN retries, about 127 s, and a peer that accepted but never
/// answers holds a read forever. So the blocking clients start each step
/// asynchronously and run their own io_context until it completes: the
/// stream's deadline then cancels the step, which answers
/// `beast::error::timeout`.

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/beast/core/error.hpp>

#include <utility>

namespace kythira::beast_deadline {

/// Starts one asynchronous operation with `start(handler)` on a stream of
/// `ioc` and runs `ioc` until it completes; the operation's error, or
/// `beast::error::timeout` once the stream's deadline passed. Only this
/// thread may run `ioc`.
template<typename Start>
[[nodiscard]] auto run(boost::asio::io_context& ioc, Start&& start) -> boost::beast::error_code {
    boost::beast::error_code result = boost::asio::error::would_block;
    std::forward<Start>(start)(
        [&result](boost::beast::error_code ec, auto&&... /*ignored*/) { result = ec; });
    ioc.restart();
    ioc.run();
    return result;
}

}  // namespace kythira::beast_deadline
