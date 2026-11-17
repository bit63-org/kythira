# `cpp-httplib` overlay port

The registry's `cpp-httplib` 0.58.0 port (vcpkg commit `e182cb4`, the
baseline `vcpkg-configuration.json` pins for this package), copied unchanged
apart from one extra patch and `port-version` 2.

## Why

The port turns on `CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO`, so every
cpp-httplib client lookup on glibc goes through `getaddrinfo_a()` and
`gai_suspend()` in `detail::getaddrinfo_with_timeout()`. glibc's
`gai_suspend()` can return 0 while the request is still in progress (its
futex wait ends on any wake-up). cpp-httplib took that return as completion
and left the function, abandoning its stack-local `struct gaicb` to glibc's
resolver thread, which then read the request and wrote its result into
whatever frame had replaced it. That thread blocks every signal, so a fault
there kills the process with no handler run: `ca_cluster_node_test` died
that way on clang++-18 arm64 CI legs.

`0001-fixed-async-resolver-instead-of-getaddrinfo-a.patch` (port-version 2,
2026-11-17) replaces port-version 1's patch, which kept calling
`gai_suspend()` while the request was in progress. That was not enough,
because glibc's asynchronous lookup API is itself unsafe under concurrent
use. Two glibc defects, both in 2.39 and still in glibc master:

1. `gai_suspend()` links a waiter that lives on its own stack into the
   request. The resolver worker stores the result *before* taking
   `__gai_requests_mutex`, then walks the waiters to notify them. A
   `gai_suspend()` that wakes in between (timeout or spurious wake-up) sees
   the request finished, skips unlinking its waiter, and returns. The worker
   then writes through the dead stack entry. A `multi_raft_node` host died
   that way inside `gai_suspend()` (g++-13 arm64 CI, 2026-11-14), and the
   wild-address crashes elsewhere may share the cause. This is glibc
   [BZ #20874](https://sourceware.org/bugzilla/show_bug.cgi?id=20874);
   the same analysis and a fix were posted in 2017
   ([comment 7](https://www.sourceware.org/ml/glibc-bugs/2017-06/msg00217.html))
   but never committed.
2. `gai_cancel()` on a request that is still queued (not yet running)
   dequeues it and returns `EAI_CANCELED`, but never sets its status. So
   `gai_error()` reports `EAI_INPROGRESS` forever, and cpp-httplib's
   "wait until it is no longer in progress" loop after a cancel never ends.
   The silent drop was reported on libc-alpha in 2017
   (["gai_cancel()"](https://patchwork.ozlabs.org/project/glibc/patch/1498487169.6717.64.camel@pbcl.net/)),
   also never fixed; no Bugzilla entry tracks it.

Both reproduce on glibc master (2.44.9000, 2026-11-17). A glibc patch
fixing both was tested locally against master; nothing is merged upstream.

The patch stops calling `getaddrinfo_a()`, `gai_suspend()`, `gai_error()`
and `gai_cancel()` at all. In their place it adds `async_resolver`, our
own implementation (not glibc's code) of the same idea with both defects
designed out: a queue served by up to
`CPPHTTPLIB_ASYNC_RESOLVER_MAX_THREADS` (default 64) worker threads, which
run plain `getaddrinfo()` and exit after a second idle.

- A request lives on the heap, shared by the caller and the queue. A caller
  that gives up only drops its reference, and no waiter ever puts memory of
  its own into shared state, which is what defect 1 needed.
- A request's status changes only under the resolver's mutex. Each request
  has its own condition variable, so a completion wakes only the threads
  waiting for that request.
- `cancel()` on a queued request removes it and marks it cancelled at once,
  which fixes defect 2. A running request cannot be stopped, but the caller
  doesn't wait for it: the worker frees it when `getaddrinfo()` returns.

`getaddrinfo_with_timeout()` submits, waits until the deadline, and on
timeout cancels and returns `EAI_AGAIN`. cpp-httplib's glibc branch is
deleted, and so is its thread-per-lookup fallback for other Unix systems,
which `async_resolver` replaces too. Two more changes:

- A numeric address (or `AI_NUMERICHOST`, or no node) is answered on the
  calling thread, since it never reaches DNS.
- Only the four request fields of `hints` are copied, and a null `service`
  or `hints` stays null.

The worker cap is 64 rather than glibc's 20 on purpose. In an overload test
(32 callers looking up a name that takes about 1 s), a 20-worker pool left
lookups of a live name queued behind the slow ones: in ASan builds, about
2,000 completed in 60 s with 20 workers, against about 4 million with 64.
Rootless Podman's DNS makes a dead peer's name take 24 s, so slow names
are a real case. A stalled DNS server still pins at most 64 threads.

Results through the patched header:

- 16 threads looking up `localhost` with 1 s timeouts: 179 us mean, against
  349-382 us for upstream's `gai_suspend()` path.
- ASan+UBSan: 66 million mixed lookups, clean. TSan: 18 million, clean.
- A race stress where each lookup takes 950-1050 ms against a 1 s timeout,
  so completion and timeout interleave: clean under ASan and TSan.
- An overload of 96 callers whose every lookup takes 3 s, with a 1 s
  timeout: all 384 calls return `EAI_AGAIN` on time, at most 64 lookups run
  at once, queued ones are cancelled cleanly, and the workers exit
  afterwards.

A 16-thread stress of the port-version 1 pattern (lookups of `localhost`
and `127.0.0.1` with 1-200 us timeouts) crashed or hung in 6 of 9 local
runs. Upstream master (0.65.0) still uses `getaddrinfo_a()` and
`gai_suspend()`.

## Removing the overlay

Drop this directory and its `overlay-ports` entry once a registry version
of cpp-httplib no longer uses `getaddrinfo_a()` on glibc (or glibc fixes
both defects), after checking that version's
`getaddrinfo_with_timeout()` by hand. When moving to a newer cpp-httplib
before then, re-copy that version's registry port here and rebase the patch.
