// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 3, requirements 12.3-12.4: key memory is locked, left out of core
// dumps, wiped on release, and a lock failure is an error unless allowed;
// harden_process() turns off core dumps and ptrace attachment.

#define BOOST_TEST_MODULE hsm_secure_arena_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/secret_bytes.hpp>
#include <kythira/hsm/secure_arena.hpp>

#include <linux/capability.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace kythira::hsm {

auto operator<<(std::ostream& out, secure_memory_error e) -> std::ostream& {
    return out << secure_memory_error_message(e);
}

auto operator<<(std::ostream& out, lock_policy p) -> std::ostream& {
    return out << (p == lock_policy::required ? "required" : "best_effort");
}

}  // namespace kythira::hsm

namespace hsm = kythira::hsm;

namespace {

constexpr int k_child_skip = 77;

/// The VmFlags line of the /proc/self/smaps entry that contains p.
auto vm_flags_of(const void* p) -> std::string {
    const auto addr = reinterpret_cast<std::uintptr_t>(p);
    std::ifstream smaps("/proc/self/smaps");
    std::string line;
    bool inside = false;
    while (std::getline(smaps, line)) {
        std::uintptr_t lo = 0;
        std::uintptr_t hi = 0;
        char dash = 0;
        std::istringstream head(line);
        if (head >> std::hex >> lo >> dash >> hi && dash == '-') {
            inside = addr >= lo && addr < hi;
            continue;
        }
        if (inside && line.starts_with("VmFlags:")) {
            return line;
        }
    }
    return {};
}

auto has_flag(const std::string& vm_flags, const std::string& flag) -> bool {
    std::istringstream in(vm_flags);
    std::string word;
    while (in >> word) {
        if (word == flag) {
            return true;
        }
    }
    return false;
}

auto failing_lock() -> std::function<int(void*, std::size_t)> {
    return [](void* /*p*/, std::size_t /*n*/) {
        errno = ENOMEM;
        return -1;
    };
}

/// Drops CAP_IPC_LOCK from this process (a forked child), so mlock is held
/// to RLIMIT_MEMLOCK even when the tests run as root.
auto drop_ipc_lock() -> bool {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, _LINUX_CAPABILITY_U32S_3> data{};
    if (::syscall(SYS_capget, &header, data.data()) != 0) {
        return false;
    }
    const auto bit = 1U << (CAP_IPC_LOCK % 32U);
    auto& word = data.at(CAP_IPC_LOCK / 32U);
    word.effective &= ~bit;
    word.permitted &= ~bit;
    word.inheritable &= ~bit;
    return ::syscall(SYS_capset, &header, data.data()) == 0;
}

/// Runs body in a forked child and returns its exit status (or -1).
template<class F> auto in_child(F body) -> int {
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::_exit(body());
    }
    int status = 0;
    if (pid < 0 || ::waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

}  // namespace

BOOST_AUTO_TEST_CASE(blocks_are_zeroed_aligned_and_owned) {
    hsm::secure_arena arena;
    auto* p = arena.allocate(100);
    BOOST_TEST(arena.owns(p));
    BOOST_TEST(reinterpret_cast<std::uintptr_t>(p) % hsm::secure_arena::granule == 0U);
    BOOST_TEST(std::all_of(p, p + 100, [](std::uint8_t b) { return b == 0; }));
    BOOST_TEST(arena.stats().in_use_bytes == 128U);
    arena.deallocate(p, 100);
    BOOST_TEST(arena.stats().in_use_bytes == 0U);
    int on_stack = 0;
    BOOST_TEST(!arena.owns(&on_stack));
}

BOOST_AUTO_TEST_CASE(a_released_block_is_wiped) {
    hsm::secure_arena arena;
    auto* keep = arena.allocate(64);  // keeps the chunk mapped
    auto* p = arena.allocate(256);
    std::fill(p, p + 256, std::uint8_t{0xA5});
    arena.deallocate(p, 256);
    // The first chunk stays mapped, so the freed bytes can be inspected.
    BOOST_TEST(arena.owns(p));
    BOOST_TEST(std::all_of(p, p + 256, [](std::uint8_t b) { return b == 0; }));
    arena.deallocate(keep, 64);
}

BOOST_AUTO_TEST_CASE(chunks_are_dontdump_and_locked_when_locking_succeeds) {
    hsm::secure_arena arena(hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort});
    auto* p = arena.allocate(32);
    const auto flags = vm_flags_of(p);
    BOOST_TEST_INFO("smaps: " << flags);
    BOOST_REQUIRE(!flags.empty());
    BOOST_TEST(has_flag(flags, "dd"));
    if (arena.stats().unlocked_chunks == 0) {
        BOOST_TEST(has_flag(flags, "lo"));
    } else {
        BOOST_TEST_MESSAGE("mlock failed on this host (RLIMIT_MEMLOCK); 'lo' not checked");
    }
    arena.deallocate(p, 32);
}

BOOST_AUTO_TEST_CASE(required_policy_refuses_unlockable_memory) {
    hsm::secure_arena arena(hsm::secure_arena_options{.lock = failing_lock()});
    auto p = arena.try_allocate(16);
    BOOST_REQUIRE(!p.has_value());
    BOOST_TEST(p.error() == hsm::secure_memory_error::lock_failed);
    BOOST_TEST(arena.stats().chunks == 0U);
    BOOST_TEST(arena.stats().lock_failures == 1U);
    BOOST_CHECK_THROW((void)arena.allocate(16), std::bad_alloc);

    hsm::secure_arena fresh(hsm::secure_arena_options{.lock = failing_lock()});
    auto started = fresh.require_locking();
    BOOST_REQUIRE(!started.has_value());
    BOOST_TEST(started.error() == hsm::secure_memory_error::lock_failed);
}

BOOST_AUTO_TEST_CASE(best_effort_uses_unlocked_memory_and_counts_it) {
    bool lock_works = false;
    hsm::secure_arena arena(hsm::secure_arena_options{
        .policy = hsm::lock_policy::best_effort, .lock = [&lock_works](void* p, std::size_t n) {
            return lock_works ? ::mlock(p, n) : (errno = ENOMEM, -1);
        }});
    auto* p = arena.allocate(16);
    BOOST_TEST(arena.stats().unlocked_chunks == 1U);
    BOOST_TEST(arena.stats().lock_failures == 1U);

    // require_locking() fails while the chunk still cannot be locked...
    auto r = arena.require_locking();
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error() == hsm::secure_memory_error::lock_failed);
    BOOST_TEST(arena.policy() == hsm::lock_policy::best_effort);

    // ...and locks it once it can (the limit was raised, say).
    lock_works = true;
    auto ok = arena.require_locking();
    if (!ok.has_value()) {
        BOOST_TEST_MESSAGE("real mlock failed on this host; required-mode upgrade not checked");
    } else {
        BOOST_TEST(arena.stats().unlocked_chunks == 0U);
        BOOST_TEST(arena.policy() == hsm::lock_policy::required);
    }
    arena.deallocate(p, 16);
}

BOOST_AUTO_TEST_CASE(require_locking_maps_a_chunk_up_front) {
    hsm::secure_arena arena;
    auto r = arena.require_locking();
    if (!r.has_value()) {
        BOOST_TEST_MESSAGE("mlock failed on this host: " << r.error());
        BOOST_TEST(r.error() == hsm::secure_memory_error::lock_failed);
        return;
    }
    BOOST_TEST(arena.stats().chunks == 1U);
    BOOST_TEST(arena.stats().unlocked_chunks == 0U);
}

BOOST_AUTO_TEST_CASE(a_zero_memlock_limit_is_a_startup_error) {
    // A real RLIMIT_MEMLOCK of zero, in a child so this process keeps its
    // limit and capabilities. CAP_IPC_LOCK is dropped first because root
    // with it ignores the limit; if mlock still works, the child says so.
    const int code = in_child([] {
        (void)drop_ipc_lock();
        const rlimit zero{0, 0};
        if (::setrlimit(RLIMIT_MEMLOCK, &zero) != 0) {
            return 2;
        }
        const long page = ::sysconf(_SC_PAGESIZE);
        void* probe = ::mmap(nullptr, static_cast<std::size_t>(page), PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (probe != MAP_FAILED && ::mlock(probe, static_cast<std::size_t>(page)) == 0) {
            return k_child_skip;
        }
        hsm::secure_arena arena;
        auto r = arena.require_locking();
        return !r.has_value() && r.error() == hsm::secure_memory_error::lock_failed ? 0 : 1;
    });
    if (code == k_child_skip) {
        BOOST_TEST_MESSAGE("mlock works under a zero RLIMIT_MEMLOCK here; nothing to prove");
        BOOST_TEST(code == k_child_skip);
    } else {
        BOOST_TEST(code == 0);
    }
}

BOOST_AUTO_TEST_CASE(a_large_request_gets_its_own_chunk_and_gives_it_back) {
    hsm::secure_arena arena(
        hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort, .chunk_size = 4096});
    auto* small = arena.allocate(32);
    auto* big = arena.allocate(3U * 4096U);
    BOOST_TEST(arena.stats().chunks == 2U);
    BOOST_TEST(arena.owns(big + (3U * 4096U) - 1U));
    arena.deallocate(big, 3U * 4096U);
    BOOST_TEST(arena.stats().chunks == 1U);
    BOOST_TEST(!arena.owns(big));
    arena.deallocate(small, 32);
    BOOST_TEST(arena.stats().chunks == 1U);  // the first chunk stays
}

BOOST_AUTO_TEST_CASE(freed_blocks_coalesce) {
    const long page = ::sysconf(_SC_PAGESIZE);
    const auto chunk = static_cast<std::size_t>(page);
    hsm::secure_arena arena(
        hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort, .chunk_size = chunk});
    std::vector<std::uint8_t*> blocks;
    for (std::size_t i = 0; i < chunk / hsm::secure_arena::granule; ++i) {
        blocks.push_back(arena.allocate(hsm::secure_arena::granule));
    }
    BOOST_TEST(arena.stats().chunks == 1U);
    std::mt19937 rng(0x5eed);
    std::ranges::shuffle(blocks, rng);
    for (auto* b : blocks) {
        arena.deallocate(b, hsm::secure_arena::granule);
    }
    // The whole chunk is one free range again, so a chunk-sized request
    // needs no new mapping.
    auto* whole = arena.allocate(chunk);
    BOOST_TEST(arena.stats().chunks == 1U);
    arena.deallocate(whole, chunk);
}

BOOST_AUTO_TEST_CASE(oversized_requests_are_refused) {
    hsm::secure_arena arena(hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort});
    auto r = arena.try_allocate(std::size_t{1} << 31U);
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error() == hsm::secure_memory_error::too_large);
}

BOOST_AUTO_TEST_CASE(concurrent_use_balances) {
    hsm::secure_arena arena(hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort});
    std::atomic<bool> bad{false};
    std::vector<std::thread> threads;
    for (unsigned t = 0; t < 8; ++t) {
        threads.emplace_back([&arena, &bad, t] {
            std::mt19937 rng(t);
            std::uniform_int_distribution<std::size_t> size(1, 600);
            for (int i = 0; i < 2000; ++i) {
                const std::size_t n = size(rng);
                auto* p = arena.allocate(n);
                if (std::any_of(p, p + n, [](std::uint8_t b) { return b != 0; })) {
                    bad = true;
                }
                std::fill(p, p + n, static_cast<std::uint8_t>(t + 1));
                arena.deallocate(p, n);
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    BOOST_TEST(!bad.load());  // every block came back wiped
    BOOST_TEST(arena.stats().in_use_bytes == 0U);
}

BOOST_AUTO_TEST_CASE(a_forked_child_sees_zeros) {
    const long page = ::sysconf(_SC_PAGESIZE);
    void* probe = ::mmap(nullptr, static_cast<std::size_t>(page), PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    BOOST_REQUIRE(probe != MAP_FAILED);
#ifdef MADV_WIPEONFORK
    const bool supported = ::madvise(probe, static_cast<std::size_t>(page), MADV_WIPEONFORK) == 0;
#else
    const bool supported = false;
#endif
    ::munmap(probe, static_cast<std::size_t>(page));
    if (!supported) {
        BOOST_TEST_MESSAGE("MADV_WIPEONFORK not supported by this kernel");
        return;
    }
    hsm::secure_arena arena(hsm::secure_arena_options{.policy = hsm::lock_policy::best_effort});
    auto* p = arena.allocate(32);
    std::fill(p, p + 32, std::uint8_t{0x5A});
    const int code = in_child(
        [p] { return std::all_of(p, p + 32, [](std::uint8_t b) { return b == 0; }) ? 0 : 1; });
    BOOST_TEST(code == 0);
    arena.deallocate(p, 32);
}

BOOST_AUTO_TEST_CASE(harden_process_disables_dumps_and_attach) {
    const int code = in_child([] {
        if (!hsm::harden_process().has_value()) {
            return 1;
        }
        if (::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
            return 2;
        }
        rlimit core{};
        if (::getrlimit(RLIMIT_CORE, &core) != 0 || core.rlim_cur != 0 || core.rlim_max != 0) {
            return 3;
        }
        return 0;
    });
    BOOST_TEST(code == 0);
}

BOOST_AUTO_TEST_CASE(secret_bytes_live_in_the_process_arena) {
    hsm::secret_bytes s(48);
    BOOST_TEST(hsm::process_arena().owns(s.data()));
    auto* raw = s.data();
    std::fill(raw, raw + 48, std::uint8_t{0x77});
    {
        hsm::secret_bytes moved(std::move(s));
        BOOST_TEST(moved.data() == raw);  // the buffer moved, no copy made
    }
    // Destroyed: the block is wiped (and still mapped in the process arena,
    // whose first chunk is kept).
    if (hsm::process_arena().owns(raw)) {
        BOOST_TEST(std::all_of(raw, raw + 48, [](std::uint8_t b) { return b == 0; }));
    }
}
