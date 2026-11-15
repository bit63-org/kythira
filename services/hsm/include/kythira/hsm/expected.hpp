// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// A value or the reason there is none: the subset of C++23 std::expected
// the HSM uses, spelled out because clang 18 (a CI compiler and the
// static-analysis one) does not provide std::expected over libstdc++ 13.
// The names and behaviour match the standard's, so moving to std::expected
// later is a change of namespace and nothing else.

#include <concepts>
#include <cstddef>
#include <exception>
#include <type_traits>
#include <utility>
#include <variant>

namespace kythira::hsm {

/// The error a failed `expected` holds, as `std::unexpected` is.
template<class E> class unexpected {
public:
    constexpr explicit unexpected(E e) : _error(std::move(e)) {}

    [[nodiscard]] constexpr auto error() const& noexcept -> const E& { return _error; }
    [[nodiscard]] constexpr auto error() & noexcept -> E& { return _error; }
    [[nodiscard]] constexpr auto error() && noexcept -> E&& { return std::move(_error); }

    friend constexpr auto operator==(const unexpected& a, const unexpected& b) -> bool {
        return a._error == b._error;
    }

private:
    E _error;
};

template<class E> unexpected(E) -> unexpected<E>;

/// Thrown by `value()` on an `expected` that holds an error.
class bad_expected_access : public std::exception {
public:
    [[nodiscard]] auto what() const noexcept -> const char* override {
        return "kythira::hsm::expected: no value";
    }
};

template<class T, class E> class expected {
public:
    using value_type = T;
    using error_type = E;

    constexpr expected()
    requires std::default_initializable<T>
        : _state(std::in_place_index<0>) {}

    template<class U = T>
    requires(!std::same_as<std::remove_cvref_t<U>, expected> &&
             !std::same_as<std::remove_cvref_t<U>, std::in_place_t> &&
             std::constructible_from<T, U>)
    constexpr expected(U&& v)  // NOLINT(google-explicit-constructor): as std::expected's
        : _state(std::in_place_index<0>, std::forward<U>(v)) {}

    template<class G>
    requires std::constructible_from<E, const G&>
    constexpr expected(const unexpected<G>& u)  // NOLINT(google-explicit-constructor)
        : _state(std::in_place_index<1>, u.error()) {}

    template<class G>
    requires std::constructible_from<E, G>
    constexpr expected(unexpected<G>&& u)  // NOLINT(google-explicit-constructor)
        : _state(std::in_place_index<1>, std::move(u).error()) {}

    template<class... Args>
    constexpr explicit expected(std::in_place_t /*tag*/, Args&&... args)
        : _state(std::in_place_index<0>, std::forward<Args>(args)...) {}

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return _state.index() == 0; }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] constexpr auto value() const& -> const T& {
        check();
        return std::get<0>(_state);
    }
    [[nodiscard]] constexpr auto value() & -> T& {
        check();
        return std::get<0>(_state);
    }
    [[nodiscard]] constexpr auto value() && -> T&& {
        check();
        return std::get<0>(std::move(_state));
    }

    constexpr auto operator*() const& noexcept -> const T& { return *std::get_if<0>(&_state); }
    constexpr auto operator*() & noexcept -> T& { return *std::get_if<0>(&_state); }
    constexpr auto operator*() && noexcept -> T&& { return std::move(*std::get_if<0>(&_state)); }
    constexpr auto operator->() const noexcept -> const T* { return std::get_if<0>(&_state); }
    constexpr auto operator->() noexcept -> T* { return std::get_if<0>(&_state); }

    [[nodiscard]] constexpr auto error() const& noexcept -> const E& {
        return *std::get_if<1>(&_state);
    }
    [[nodiscard]] constexpr auto error() & noexcept -> E& { return *std::get_if<1>(&_state); }
    [[nodiscard]] constexpr auto error() && noexcept -> E&& {
        return std::move(*std::get_if<1>(&_state));
    }

    template<class U> [[nodiscard]] constexpr auto value_or(U&& fallback) const& -> T {
        return has_value() ? **this : static_cast<T>(std::forward<U>(fallback));
    }
    template<class U> [[nodiscard]] constexpr auto value_or(U&& fallback) && -> T {
        return has_value() ? std::move(**this) : static_cast<T>(std::forward<U>(fallback));
    }

    template<class... Args> constexpr auto emplace(Args&&... args) -> T& {
        return _state.template emplace<0>(std::forward<Args>(args)...);
    }

    template<class U>
    requires(!std::same_as<std::remove_cvref_t<U>, expected>)
    friend constexpr auto operator==(const expected& x, const U& v) -> bool {
        return x.has_value() && *x == v;
    }
    template<class G>
    friend constexpr auto operator==(const expected& x, const unexpected<G>& u) -> bool {
        return !x.has_value() && x.error() == u.error();
    }

private:
    constexpr void check() const {
        if (!has_value()) {
            throw bad_expected_access{};
        }
    }

    std::variant<T, E> _state;
};

/// Success with no value, or the error.
template<class E> class expected<void, E> {
public:
    using value_type = void;
    using error_type = E;

    constexpr expected() noexcept = default;

    template<class G>
    requires std::constructible_from<E, const G&>
    constexpr expected(const unexpected<G>& u)  // NOLINT(google-explicit-constructor)
        : _state(std::in_place_index<1>, u.error()) {}

    template<class G>
    requires std::constructible_from<E, G>
    constexpr expected(unexpected<G>&& u)  // NOLINT(google-explicit-constructor)
        : _state(std::in_place_index<1>, std::move(u).error()) {}

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return _state.index() == 0; }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    constexpr void value() const {
        if (!has_value()) {
            throw bad_expected_access{};
        }
    }
    constexpr void operator*() const noexcept {}

    [[nodiscard]] constexpr auto error() const& noexcept -> const E& {
        return *std::get_if<1>(&_state);
    }
    [[nodiscard]] constexpr auto error() && noexcept -> E&& {
        return std::move(*std::get_if<1>(&_state));
    }

    template<class G>
    friend constexpr auto operator==(const expected& x, const unexpected<G>& u) -> bool {
        return !x.has_value() && x.error() == u.error();
    }

private:
    std::variant<std::monostate, E> _state;
};

}  // namespace kythira::hsm
