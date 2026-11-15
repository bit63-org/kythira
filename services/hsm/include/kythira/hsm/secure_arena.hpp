// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Locked, non-dumpable memory for unwrapped key material (requirement
// 12.3-12.4).
//
// A secure_arena hands out blocks from anonymous mmap'd chunks that are
// mlock'ed (never written to swap), marked MADV_DONTDUMP (left out of core
// dumps) and, where the kernel has it, MADV_WIPEONFORK (a forked child sees
// zeros). Every block is wiped with OPENSSL_cleanse when it is released and
// every chunk again before it is unmapped.
//
// Locking can fail: RLIMIT_MEMLOCK is often 64 KiB in containers. Under
// lock_policy::required (what the HSM module uses unless the operator sets
// the allow-unlocked flag) a chunk that cannot be locked is unmapped and the
// allocation fails, and require_locking() reports the failure at startup.
// Under lock_policy::best_effort the chunk is used anyway and counted in
// stats().unlocked_chunks, so the caller can warn.
//
// harden_process() sets PR_SET_DUMPABLE=0 (no core dumps, no ptrace attach
// by non-root) and RLIMIT_CORE=0. None of this stops root or a hypervisor;
// the module documentation says so.

#include <openssl/crypto.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <kythira/hsm/expected.hpp>
#include <functional>
#include <map>
#include <mutex>
#include <new>
#include <string_view>
#include <type_traits>
#include <vector>

namespace kythira::hsm {

enum class secure_memory_error : std::uint8_t {
    map_failed,
    lock_failed,
    dontdump_failed,
    dumpable_failed,
    core_limit_failed,
    too_large,
};

[[nodiscard]] constexpr auto secure_memory_error_message(secure_memory_error e) noexcept
    -> std::string_view {
    switch (e) {
        case secure_memory_error::map_failed:
            return "mmap of a secure memory chunk failed";
        case secure_memory_error::lock_failed:
            return "mlock of secure memory failed (raise RLIMIT_MEMLOCK, grant CAP_IPC_LOCK, "
                   "or allow unlocked key memory explicitly)";
        case secure_memory_error::dontdump_failed:
            return "madvise(MADV_DONTDUMP) on secure memory failed";
        case secure_memory_error::dumpable_failed:
            return "prctl(PR_SET_DUMPABLE, 0) failed";
        case secure_memory_error::core_limit_failed:
            return "setrlimit(RLIMIT_CORE, 0) failed";
        case secure_memory_error::too_large:
            return "secure memory request is too large";
    }
    return "unknown secure memory error";
}

enum class lock_policy : std::uint8_t {
    /// A chunk that cannot be locked is an error (the default for the module).
    required,
    /// Use unlocked chunks and count them (development, or an explicit flag).
    best_effort,
};

struct secure_arena_options {
    lock_policy policy = lock_policy::required;
    /// Size of each chunk, rounded up to whole pages. Requests larger than a
    /// chunk get a chunk of their own.
    std::size_t chunk_size = 64U * 1024U;
    /// The lock call; tests replace it to simulate RLIMIT_MEMLOCK failures
    /// without depending on the runner's limits or capabilities.
    std::function<int(void*, std::size_t)> lock = [](void* p, std::size_t n) {
        return ::mlock(p, n);
    };
};

struct secure_arena_stats {
    std::size_t chunks = 0;
    std::size_t unlocked_chunks = 0;
    std::size_t mapped_bytes = 0;
    std::size_t in_use_bytes = 0;
    std::size_t lock_failures = 0;
};

class secure_arena {
public:
    /// Blocks are aligned to, and sized in multiples of, this many bytes.
    static constexpr std::size_t granule = 32;

    explicit secure_arena(secure_arena_options options = {})
        : _options(std::move(options)), _page(page_size()) {
        _options.chunk_size = round_up(std::max(_options.chunk_size, _page), _page);
    }

    secure_arena(const secure_arena&) = delete;
    auto operator=(const secure_arena&) -> secure_arena& = delete;
    secure_arena(secure_arena&&) = delete;
    auto operator=(secure_arena&&) -> secure_arena& = delete;

    ~secure_arena() {
        const std::scoped_lock guard(_mutex);
        for (auto& c : _chunks) {
            unmap(c);
        }
    }

    /// Switches to lock_policy::required and proves it can be met: every
    /// existing chunk is locked (or the call fails), and if there is none
    /// yet, one is mapped and locked now, so an RLIMIT_MEMLOCK problem is a
    /// startup error rather than the first key operation's.
    [[nodiscard]] auto require_locking() -> expected<void, secure_memory_error> {
        const std::scoped_lock guard(_mutex);
        for (auto& c : _chunks) {
            if (!c.locked) {
                if (_options.lock(c.base, c.size) != 0) {
                    ++_lock_failures;
                    return unexpected(secure_memory_error::lock_failed);
                }
                c.locked = true;
            }
        }
        _options.policy = lock_policy::required;
        if (_chunks.empty()) {
            auto made = map_chunk(_options.chunk_size);
            if (!made) {
                return unexpected(made.error());
            }
        }
        return {};
    }

    /// A zero-filled block of at least n bytes, or why there is none.
    [[nodiscard]] auto try_allocate(std::size_t n) -> expected<std::uint8_t*, secure_memory_error> {
        if (n == 0) {
            n = 1;
        }
        if (n > max_request) {
            return unexpected(secure_memory_error::too_large);
        }
        const std::size_t size = round_up(n, granule);
        const std::scoped_lock guard(_mutex);
        for (auto& c : _chunks) {
            if (auto* p = take(c, size)) {
                return p;
            }
        }
        auto made = map_chunk(std::max(_options.chunk_size, round_up(size, _page)));
        if (!made) {
            return unexpected(made.error());
        }
        return take(*made.value(), size);
    }

    /// try_allocate for allocator use: throws std::bad_alloc on failure.
    [[nodiscard]] auto allocate(std::size_t n) -> std::uint8_t* {
        auto p = try_allocate(n);
        if (!p) {
            throw std::bad_alloc();
        }
        return *p;
    }

    /// Wipes and returns a block. n is the size that was asked for.
    void deallocate(std::uint8_t* p, std::size_t n) noexcept {
        if (p == nullptr) {
            return;
        }
        const std::size_t size = round_up(std::max<std::size_t>(n, 1), granule);
        const std::scoped_lock guard(_mutex);
        for (auto it = _chunks.begin(); it != _chunks.end(); ++it) {
            if (p >= it->base && p < it->base + it->size) {
                OPENSSL_cleanse(p, size);
                give_back(*it, static_cast<std::size_t>(p - it->base), size);
                _in_use -= size;
                // Keep the first chunk mapped (it proved locking works);
                // return later ones to the kernel once empty.
                if (it != _chunks.begin() && it->used == 0) {
                    unmap(*it);
                    _chunks.erase(it);
                }
                return;
            }
        }
        // Not ours: a programming error. Do not touch memory we do not own.
    }

    /// True when p points into memory this arena mapped.
    [[nodiscard]] auto owns(const void* p) const noexcept -> bool {
        const std::scoped_lock guard(_mutex);
        const auto* b = static_cast<const std::uint8_t*>(p);
        return std::ranges::any_of(
            _chunks, [b](const chunk& c) { return b >= c.base && b < c.base + c.size; });
    }

    [[nodiscard]] auto stats() const -> secure_arena_stats {
        const std::scoped_lock guard(_mutex);
        secure_arena_stats s;
        s.chunks = _chunks.size();
        for (const auto& c : _chunks) {
            s.mapped_bytes += c.size;
            if (!c.locked) {
                ++s.unlocked_chunks;
            }
        }
        s.in_use_bytes = _in_use;
        s.lock_failures = _lock_failures;
        return s;
    }

    [[nodiscard]] auto policy() const -> lock_policy {
        const std::scoped_lock guard(_mutex);
        return _options.policy;
    }

private:
    static constexpr std::size_t max_request = std::size_t{1} << 30U;

    struct chunk {
        std::uint8_t* base = nullptr;
        std::size_t size = 0;
        std::size_t used = 0;
        bool locked = false;
        /// Free ranges: offset -> length, coalesced on release.
        std::map<std::size_t, std::size_t> free;
    };

    static auto page_size() noexcept -> std::size_t {
        const long p = ::sysconf(_SC_PAGESIZE);
        return p > 0 ? static_cast<std::size_t>(p) : std::size_t{4096};
    }

    static constexpr auto round_up(std::size_t n, std::size_t to) noexcept -> std::size_t {
        return (n + to - 1) / to * to;
    }

    auto map_chunk(std::size_t size) -> expected<chunk*, secure_memory_error> {
        void* p = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return unexpected(secure_memory_error::map_failed);
        }
        chunk c;
        c.base = static_cast<std::uint8_t*>(p);
        c.size = size;
        if (::madvise(p, size, MADV_DONTDUMP) != 0) {
            ::munmap(p, size);
            return unexpected(secure_memory_error::dontdump_failed);
        }
#ifdef MADV_WIPEONFORK
        // Older kernels refuse it (EINVAL); the lock and DONTDUMP still hold.
        (void)::madvise(p, size, MADV_WIPEONFORK);
#endif
        c.locked = _options.lock(p, size) == 0;
        if (!c.locked) {
            ++_lock_failures;
            if (_options.policy == lock_policy::required) {
                ::munmap(p, size);
                return unexpected(secure_memory_error::lock_failed);
            }
        }
        c.free.emplace(0, size);
        _chunks.push_back(std::move(c));
        return &_chunks.back();
    }

    static void unmap(chunk& c) noexcept {
        if (c.base == nullptr) {
            return;
        }
        OPENSSL_cleanse(c.base, c.size);
        if (c.locked) {
            ::munlock(c.base, c.size);
        }
        ::munmap(c.base, c.size);
        c.base = nullptr;
    }

    /// First fit within one chunk.
    auto take(chunk& c, std::size_t size) -> std::uint8_t* {
        for (auto it = c.free.begin(); it != c.free.end(); ++it) {
            if (it->second >= size) {
                const std::size_t offset = it->first;
                const std::size_t rest = it->second - size;
                c.free.erase(it);
                if (rest != 0) {
                    c.free.emplace(offset + size, rest);
                }
                c.used += size;
                _in_use += size;
                return c.base + offset;
            }
        }
        return nullptr;
    }

    static void give_back(chunk& c, std::size_t offset, std::size_t size) {
        c.used -= size;
        auto [it, inserted] = c.free.emplace(offset, size);
        if (!inserted) {
            return;  // double free; the range is already free
        }
        auto next = std::next(it);
        if (next != c.free.end() && it->first + it->second == next->first) {
            it->second += next->second;
            c.free.erase(next);
        }
        if (it != c.free.begin()) {
            auto prev = std::prev(it);
            if (prev->first + prev->second == it->first) {
                prev->second += it->second;
                c.free.erase(it);
            }
        }
    }

    secure_arena_options _options;
    std::size_t _page;
    mutable std::mutex _mutex;
    // map_chunk's returned pointer is used before the next push_back, so
    // a vector's reallocation never leaves it dangling.
    std::vector<chunk> _chunks;
    std::size_t _in_use = 0;
    std::size_t _lock_failures = 0;
};

/// The arena key material uses by default (secret_bytes, the key cache).
/// It starts best-effort so tools and tests run under any RLIMIT_MEMLOCK;
/// the HSM module calls require_locking() on it at startup unless the
/// operator allowed unlocked key memory.
[[nodiscard]] inline auto process_arena() -> secure_arena& {
    static secure_arena arena(secure_arena_options{.policy = lock_policy::best_effort});
    return arena;
}

/// Disables core dumps and ptrace attachment by non-root for this process.
[[nodiscard]] inline auto harden_process() -> expected<void, secure_memory_error> {
    if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return unexpected(secure_memory_error::dumpable_failed);
    }
    const rlimit none{0, 0};
    if (::setrlimit(RLIMIT_CORE, &none) != 0) {
        return unexpected(secure_memory_error::core_limit_failed);
    }
    return {};
}

/// What the HSM module (and hsm_node) run before touching key material:
/// harden the process, then, unless the operator explicitly allowed
/// unlocked key memory, prove the process arena can be locked. Requirement
/// 12.4: a lock failure is a startup error unless a flag allows it.
[[nodiscard]] inline auto prepare_key_memory(bool allow_unlocked)
    -> expected<void, secure_memory_error> {
    if (auto hardened = harden_process(); !hardened) {
        return hardened;
    }
    if (allow_unlocked) {
        return {};
    }
    return process_arena().require_locking();
}

/// A standard allocator over an arena (process_arena() by default), for
/// containers that hold key bytes.
template<class T> class secure_allocator {
public:
    using value_type = T;
    // Moving a container moves its buffer with it, never byte by byte into
    // a fresh block (which would leave a second copy until the wipe).
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;

    secure_allocator() noexcept : _arena(&process_arena()) {}
    explicit secure_allocator(secure_arena& arena) noexcept : _arena(&arena) {}
    template<class U>
    secure_allocator(
        const secure_allocator<U>& other) noexcept  // NOLINT(google-explicit-constructor)
        : _arena(other.arena()) {}

    [[nodiscard]] auto allocate(std::size_t n) -> T* {
        if (n > std::size_t{1} << 30U) {
            throw std::bad_alloc();
        }
        // The arena aligns every block to `granule`, enough for byte and
        // word types.
        static_assert(alignof(T) <= secure_arena::granule);
        return reinterpret_cast<T*>(_arena->allocate(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t n) noexcept {
        _arena->deallocate(reinterpret_cast<std::uint8_t*>(p), n * sizeof(T));
    }

    [[nodiscard]] auto arena() const noexcept -> secure_arena* { return _arena; }

    template<class U> auto operator==(const secure_allocator<U>& other) const noexcept -> bool {
        return _arena == other.arena();
    }

private:
    secure_arena* _arena;
};

}  // namespace kythira::hsm
