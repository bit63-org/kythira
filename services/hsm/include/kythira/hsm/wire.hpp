// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM's client wire protocol (.kiro/specs/virtual-hsm/ task 9,
// requirements 2.4 and 8.1): what libkythira_pkcs11.so (task 10) and any
// other out-of-process client speak to a node, over mutual TLS 1.3 or a
// Unix socket. One request is one PKCS#11 call, so the server is a thin
// dispatcher in front of the same native_client co-located modules use
// (wire_server.hpp), and the client (wire_client.hpp) mirrors that class.
//
// Framing. Each message is a 4-byte big-endian length and that many
// bytes; a zero length or one above the receiver's limit ends the
// connection. A request is
//
//   u8 version (1), u32 op, the op's arguments
//
// and its response
//
//   u64 CK_RV, and the op's results only when the CK_RV is CKR_OK.
//
// Integers are big-endian, byte strings a u32 length and the bytes (the
// byte_writer of codec.hpp, which the Raft commands use too). A template
// travels as attribute_map::encode() gives it. Attribute values travel as
// PKCS#11 lays them out in memory, so a CK_ULONG attribute is 8
// little-endian bytes: the client library is built for 64-bit Linux, the
// same CK_ULONG as the server's.
//
// Mechanism parameters that hold pointers (GCM, OAEP, EdDSA, ECDH1, HKDF)
// travel field by field, and so does PSS's, whose CK_ULONGs would
// otherwise be in the client's layout; the server rebuilds each
// structure around its own buffers. The only parameters sent as raw bytes
// are the IVs of the AES modes that take one. The server refuses a raw
// parameter for any other mechanism, so a client can never hand it a
// structure whose pointers it would follow.
//
// Why not protobuf, as the design first said: the protocol is one
// request per call with a few fixed fields, the HSM's build needs only
// OpenSSL, and the client library links its dependencies statically into
// every process that loads it; the codec the Raft commands already use
// keeps it small and adds nothing to link.
//
// Buffers that may hold a PIN, a template with a key value or decrypted
// bytes are wiped (OPENSSL_cleanse) once the call is done, on both sides.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/client_types.hpp>
#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/pkcs11.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace kythira::hsm::wire {

inline constexpr std::uint8_t protocol_version = 1;
/// A frame can carry a multi-part operation's whole input (the session
/// layer buffers up to 16 MiB) plus its framing.
inline constexpr std::uint32_t default_max_frame_bytes = (16U << 20U) + (64U << 10U);

/// One per native_client call, plus hello and the mechanism queries. The
/// numbers are the protocol: never renumber, only add.
enum class op : std::uint32_t {
    /// -> u8 protocol version, u32 the server's frame limit, str the
    /// identity this connection was authenticated as.
    hello = 1,
    get_slot_list = 2,
    get_token_info = 3,
    init_token = 4,
    open_session = 5,
    close_session = 6,
    close_all_sessions = 7,
    get_session_info = 8,
    login = 9,
    logout = 10,
    init_pin = 11,
    set_pin = 12,
    generate_key = 13,
    generate_key_pair = 14,
    destroy_object = 15,
    get_attribute_value = 16,
    set_attribute_value = 17,
    create_object = 18,
    copy_object = 19,
    wrap_key = 20,
    unwrap_key = 21,
    derive_key = 22,
    find_objects_init = 23,
    find_objects = 24,
    find_objects_final = 25,
    sign_init = 26,
    sign = 27,
    sign_update = 28,
    sign_final = 29,
    verify_init = 30,
    verify = 31,
    verify_update = 32,
    verify_final = 33,
    encrypt_init = 34,
    encrypt = 35,
    encrypt_update = 36,
    encrypt_final = 37,
    decrypt_init = 38,
    decrypt = 39,
    decrypt_update = 40,
    decrypt_final = 41,
    digest_init = 42,
    digest = 43,
    digest_update = 44,
    digest_final = 45,
    generate_random = 46,
    get_mechanism_list = 47,
    get_mechanism_info = 48,
};

// --- Byte helpers ------------------------------------------------------------

inline auto as_bytes(std::span<const std::uint8_t> v) -> std::span<const std::byte> {
    return {reinterpret_cast<const std::byte*>(v.data()), v.size()};
}

inline auto as_u8(std::span<const std::byte> v) -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(v.data()), v.size()};
}

inline void wipe(std::vector<std::byte>& v) noexcept {
    if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size());
    }
}

inline void wipe(std::vector<std::uint8_t>& v) noexcept {
    if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size());
    }
}

/// A buffer wiped when it goes out of scope.
struct wiped_buffer {
    std::vector<std::byte> bytes;
    wiped_buffer() = default;
    explicit wiped_buffer(std::vector<std::byte> b) : bytes(std::move(b)) {}
    wiped_buffer(const wiped_buffer&) = delete;
    auto operator=(const wiped_buffer&) -> wiped_buffer& = delete;
    wiped_buffer(wiped_buffer&&) = delete;
    auto operator=(wiped_buffer&&) -> wiped_buffer& = delete;
    ~wiped_buffer() { wipe(bytes); }
};

// --- Streams and frames ------------------------------------------------------

/// A connected byte stream: a socket, or TLS over one.
class stream {
public:
    stream() = default;
    stream(const stream&) = delete;
    auto operator=(const stream&) -> stream& = delete;
    stream(stream&&) = delete;
    auto operator=(stream&&) -> stream& = delete;
    virtual ~stream() = default;

    /// False on end of stream, an error or a timeout.
    [[nodiscard]] virtual auto read_exact(std::span<std::byte> out) -> bool = 0;
    [[nodiscard]] virtual auto write_all(std::span<const std::byte> in) -> bool = 0;
};

/// One write, so the header and the payload go out in one TLS record and
/// one segment (the copy is wiped).
inline auto write_frame(stream& s, std::span<const std::byte> payload) -> bool {
    if (payload.empty() || payload.size() > UINT32_MAX) {
        return false;
    }
    const auto n = static_cast<std::uint32_t>(payload.size());
    wiped_buffer frame;
    frame.bytes.reserve(payload.size() + 4);
    for (int shift = 24; shift >= 0; shift -= 8) {
        frame.bytes.push_back(static_cast<std::byte>(n >> static_cast<unsigned>(shift)));
    }
    frame.bytes.insert(frame.bytes.end(), payload.begin(), payload.end());
    return s.write_all(frame.bytes);
}

/// The next frame, or nothing at the end of the stream, on an error, or
/// when the frame is empty or longer than `max_bytes`.
inline auto read_frame(stream& s, std::uint32_t max_bytes = default_max_frame_bytes)
    -> std::optional<std::vector<std::byte>> {
    std::array<std::byte, 4> header{};
    if (!s.read_exact(header)) {
        return std::nullopt;
    }
    std::uint32_t n = 0;
    for (auto b : header) {
        n = (n << 8U) | static_cast<std::uint32_t>(b);
    }
    if (n == 0 || n > max_bytes) {
        return std::nullopt;
    }
    std::vector<std::byte> out(n);
    if (!s.read_exact(out)) {
        wipe(out);
        return std::nullopt;
    }
    return out;
}

/// A socket, read and written directly (the Unix socket); closed with the
/// stream when `owns`.
class fd_stream final : public stream {
public:
    explicit fd_stream(int fd, bool owns = true) noexcept : _fd(fd), _owns(owns) {}
    fd_stream(const fd_stream&) = delete;
    auto operator=(const fd_stream&) -> fd_stream& = delete;
    fd_stream(fd_stream&&) = delete;
    auto operator=(fd_stream&&) -> fd_stream& = delete;
    ~fd_stream() override {
        if (_owns && _fd >= 0) {
            ::close(_fd);
        }
    }

    [[nodiscard]] auto read_exact(std::span<std::byte> out) -> bool override {
        std::size_t at = 0;
        while (at < out.size()) {
            const auto r = ::recv(_fd, out.data() + at, out.size() - at, 0);
            if (r < 0 && errno == EINTR) {
                continue;
            }
            if (r <= 0) {
                return false;
            }
            at += static_cast<std::size_t>(r);
        }
        return true;
    }

    [[nodiscard]] auto write_all(std::span<const std::byte> in) -> bool override {
        std::size_t at = 0;
        while (at < in.size()) {
            const auto r = ::send(_fd, in.data() + at, in.size() - at, MSG_NOSIGNAL);
            if (r < 0 && errno == EINTR) {
                continue;
            }
            if (r <= 0) {
                return false;
            }
            at += static_cast<std::size_t>(r);
        }
        return true;
    }

    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }

private:
    int _fd;
    bool _owns;
};

namespace detail {

// A socket BIO that writes with MSG_NOSIGNAL. OpenSSL's own socket BIO
// writes with write(), which raises SIGPIPE when the peer has gone; the
// server could ignore SIGPIPE process-wide, but the client library lives
// in someone else's process and must not change its signal handling.

/// The BIO's data is a heap int holding the descriptor, freed with the BIO.
inline auto bio_fd(BIO* b) -> int {
    return *static_cast<const int*>(BIO_get_data(b));
}

inline auto bio_write(BIO* b, const char* data, int len) -> int {
    for (;;) {
        const auto r = ::send(bio_fd(b), data, static_cast<std::size_t>(len), MSG_NOSIGNAL);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return static_cast<int>(r);
    }
}

inline auto bio_read(BIO* b, char* data, int len) -> int {
    for (;;) {
        const auto r = ::recv(bio_fd(b), data, static_cast<std::size_t>(len), 0);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return static_cast<int>(r);
    }
}

inline auto bio_ctrl(BIO* /*b*/, int cmd, long /*num*/, void* /*ptr*/) -> long {
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

inline auto bio_create(BIO* b) -> int {
    BIO_set_data(b, nullptr);
    BIO_set_init(b, 1);
    return 1;
}

inline auto bio_destroy(BIO* b) -> int {
    delete static_cast<int*>(BIO_get_data(b));  // NOLINT(cppcoreguidelines-owning-memory)
    BIO_set_data(b, nullptr);
    return 1;
}

inline auto nosignal_socket_method() -> const BIO_METHOD* {
    static BIO_METHOD* const method = [] {
        BIO_METHOD* m = BIO_meth_new(
            BIO_get_new_index() | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR, "kythira-hsm-socket");
        if (m != nullptr) {
            BIO_meth_set_write(m, bio_write);
            BIO_meth_set_read(m, bio_read);
            BIO_meth_set_ctrl(m, bio_ctrl);
            BIO_meth_set_create(m, bio_create);
            BIO_meth_set_destroy(m, bio_destroy);
        }
        return m;
    }();
    return method;
}

}  // namespace detail

/// Attaches `fd` to `ssl` through a BIO that never raises SIGPIPE. False
/// when OpenSSL could not make the BIO. The socket stays the caller's.
inline auto attach_socket(SSL* ssl, int fd) -> bool {
    const BIO_METHOD* m = detail::nosignal_socket_method();
    BIO* b = m == nullptr ? nullptr : BIO_new(m);
    if (b == nullptr) {
        return false;
    }
    BIO_set_data(b, new int{fd});  // NOLINT(cppcoreguidelines-owning-memory): bio_destroy frees it
    SSL_set_bio(ssl, b, b);
    return true;
}

/// TLS over a socket, both owned; the handshake is already done.
class tls_stream final : public stream {
public:
    tls_stream(SSL* ssl, int fd) noexcept : _ssl(ssl), _fd(fd) {}
    tls_stream(const tls_stream&) = delete;
    auto operator=(const tls_stream&) -> tls_stream& = delete;
    tls_stream(tls_stream&&) = delete;
    auto operator=(tls_stream&&) -> tls_stream& = delete;
    ~tls_stream() override {
        if (_ssl != nullptr) {
            (void)SSL_shutdown(_ssl);  // close_notify, without waiting for the peer's
            SSL_free(_ssl);
        }
        if (_fd >= 0) {
            ::close(_fd);
        }
    }

    [[nodiscard]] auto read_exact(std::span<std::byte> out) -> bool override {
        std::size_t at = 0;
        while (at < out.size()) {
            std::size_t got = 0;
            if (SSL_read_ex(_ssl, out.data() + at, out.size() - at, &got) != 1) {
                return false;
            }
            at += got;
        }
        return true;
    }

    [[nodiscard]] auto write_all(std::span<const std::byte> in) -> bool override {
        std::size_t at = 0;
        while (at < in.size()) {
            std::size_t put = 0;
            if (SSL_write_ex(_ssl, in.data() + at, in.size() - at, &put) != 1) {
                return false;
            }
            at += put;
        }
        return true;
    }

    [[nodiscard]] auto ssl() const noexcept -> SSL* { return _ssl; }

private:
    SSL* _ssl;
    int _fd;
};

// --- Requests and responses --------------------------------------------------

inline auto request(op o) -> byte_writer {
    byte_writer w;
    w.u8(protocol_version).u32(static_cast<std::uint32_t>(o));
    return w;
}

inline auto put_ulongs(byte_writer& w, std::span<const CK_ULONG> v) -> byte_writer& {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (auto x : v) {
        w.u64(x);
    }
    return w;
}

/// At most `limit` CK_ULONGs, so a hostile count cannot reserve memory
/// the frame does not hold.
inline auto get_ulongs(byte_reader& r, std::size_t limit = default_max_frame_bytes / 8)
    -> std::vector<CK_ULONG> {
    const auto n = r.u32();
    if (n > limit) {
        throw std::invalid_argument("hsm wire: too many values");
    }
    std::vector<CK_ULONG> out;
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(static_cast<CK_ULONG>(r.u64()));
    }
    return out;
}

inline auto put_attributes(byte_writer& w, const attribute_map& m) -> byte_writer& {
    auto encoded = m.encode();
    w.bytes(encoded);
    wipe(encoded);
    return w;
}

/// A template; a malformed one is CKR_ATTRIBUTE_VALUE_INVALID, as
/// attribute_map::decode answers.
inline auto get_attributes(byte_reader& r) -> ck_result<attribute_map> {
    auto encoded = r.bytes();
    auto m = attribute_map::decode(encoded);
    wipe(encoded);
    return m;
}

inline auto put_token_info(byte_writer& w, const token_info& t) -> byte_writer& {
    return w.str(t.label).u64(t.flags).u64(t.session_count).u64(t.rw_session_count);
}

inline auto get_token_info(byte_reader& r) -> token_info {
    token_info t;
    t.label = r.str();
    t.flags = static_cast<CK_FLAGS>(r.u64());
    t.session_count = static_cast<CK_ULONG>(r.u64());
    t.rw_session_count = static_cast<CK_ULONG>(r.u64());
    return t;
}

inline auto put_session_info(byte_writer& w, const session_info& s) -> byte_writer& {
    return w.u64(s.slot).u64(s.state).u64(s.flags);
}

inline auto get_session_info(byte_reader& r) -> session_info {
    session_info s;
    s.slot = static_cast<CK_SLOT_ID>(r.u64());
    s.state = static_cast<CK_STATE>(r.u64());
    s.flags = static_cast<CK_FLAGS>(r.u64());
    return s;
}

inline auto put_attribute_values(byte_writer& w, const std::vector<attribute_value>& values)
    -> byte_writer& {
    w.u32(static_cast<std::uint32_t>(values.size()));
    for (const auto& v : values) {
        w.u64(v.type).u64(v.rv).u8(v.value ? 1 : 0);
        if (v.value) {
            w.bytes(*v.value);
        }
    }
    return w;
}

inline auto get_attribute_values(byte_reader& r) -> std::vector<attribute_value> {
    const auto n = r.u32();
    std::vector<attribute_value> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        attribute_value v;
        v.type = static_cast<CK_ATTRIBUTE_TYPE>(r.u64());
        v.rv = static_cast<CK_RV>(r.u64());
        if (r.u8() != 0) {
            v.value = r.bytes();
        }
        out.push_back(std::move(v));
    }
    return out;
}

// --- Mechanisms --------------------------------------------------------------

/// How a mechanism's parameter travels.
enum class param_kind : std::uint8_t {
    none = 0,
    /// The parameter's bytes (an IV).
    raw = 1,
    gcm = 2,
    oaep = 3,
    pss = 4,
    eddsa = 5,
    ecdh1 = 6,
    hkdf = 7,
};

/// The structured kind `type`'s parameter has, `raw` for the AES IVs, and
/// `none` for every mechanism that takes no parameter (or one this token
/// does not implement, which then travels as nothing and is refused).
[[nodiscard]] constexpr auto param_kind_of(CK_MECHANISM_TYPE type) noexcept -> param_kind {
    switch (type) {
        case CKM_AES_GCM:
            return param_kind::gcm;
        case CKM_RSA_PKCS_OAEP:
            return param_kind::oaep;
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA224_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return param_kind::pss;
        case CKM_EDDSA:
            return param_kind::eddsa;
        case CKM_ECDH1_DERIVE:
        case CKM_ECDH1_COFACTOR_DERIVE:
            return param_kind::ecdh1;
        case CKM_HKDF_DERIVE:
        case CKM_HKDF_DATA:
            return param_kind::hkdf;
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
        case CKM_AES_KEY_WRAP_KWP:
            return param_kind::raw;
        default:
            return param_kind::none;
    }
}

namespace detail {

/// A caller's (pointer, length) as a span; nothing when a null pointer has
/// a length.
inline auto caller_span(const void* p, CK_ULONG len)
    -> std::optional<std::span<const std::uint8_t>> {
    if (p == nullptr) {
        if (len != 0) {
            return std::nullopt;
        }
        return std::span<const std::uint8_t>{};
    }
    return std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(p), len);
}

template<class P> auto param_of(const CK_MECHANISM& m) -> const P* {
    if (m.pParameter == nullptr || m.ulParameterLen != sizeof(P)) {
        return nullptr;
    }
    return static_cast<const P*>(m.pParameter);
}

}  // namespace detail

/// Writes a caller's mechanism: u64 type, u8 kind, then the kind's fields.
/// CKR_MECHANISM_PARAM_INVALID when the parameter is not the size of its
/// structure or a pointer in it is null with a length; nothing is written
/// then, and the request must not be sent.
inline auto put_mechanism(byte_writer& w, const CK_MECHANISM& m) -> CK_RV {
    using detail::caller_span;
    using detail::param_of;
    if (m.pParameter == nullptr) {
        if (m.ulParameterLen != 0) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        w.u64(m.mechanism).u8(static_cast<std::uint8_t>(param_kind::none));
        return CKR_OK;
    }
    const auto kind = param_kind_of(m.mechanism);
    switch (kind) {
        case param_kind::none:
            // A parameter for a mechanism that takes none: the server
            // would refuse it, so refuse it here without sending it.
            return CKR_MECHANISM_PARAM_INVALID;
        case param_kind::raw: {
            const auto raw = caller_span(m.pParameter, m.ulParameterLen);
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind)).bytes(*raw);
            return CKR_OK;
        }
        case param_kind::gcm: {
            const auto* p = param_of<CK_GCM_PARAMS>(m);
            const auto iv = p != nullptr ? caller_span(p->pIv, p->ulIvLen) : std::nullopt;
            const auto aad = p != nullptr ? caller_span(p->pAAD, p->ulAADLen) : std::nullopt;
            if (!iv || !aad) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.bytes(*iv).u64(p->ulIvBits).bytes(*aad).u64(p->ulTagBits);
            return CKR_OK;
        }
        case param_kind::oaep: {
            const auto* p = param_of<CK_RSA_PKCS_OAEP_PARAMS>(m);
            const auto src =
                p != nullptr ? caller_span(p->pSourceData, p->ulSourceDataLen) : std::nullopt;
            if (!src) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.u64(p->hashAlg).u64(p->mgf).u64(p->source).bytes(*src);
            return CKR_OK;
        }
        case param_kind::pss: {
            const auto* p = param_of<CK_RSA_PKCS_PSS_PARAMS>(m);
            if (p == nullptr) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.u64(p->hashAlg).u64(p->mgf).u64(p->sLen);
            return CKR_OK;
        }
        case param_kind::eddsa: {
            const auto* p = param_of<CK_EDDSA_PARAMS>(m);
            const auto ctx =
                p != nullptr ? caller_span(p->pContextData, p->ulContextDataLen) : std::nullopt;
            if (!ctx) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.u8(p->phFlag != CK_FALSE ? 1 : 0).bytes(*ctx);
            return CKR_OK;
        }
        case param_kind::ecdh1: {
            const auto* p = param_of<CK_ECDH1_DERIVE_PARAMS>(m);
            const auto shared =
                p != nullptr ? caller_span(p->pSharedData, p->ulSharedDataLen) : std::nullopt;
            const auto pub =
                p != nullptr ? caller_span(p->pPublicData, p->ulPublicDataLen) : std::nullopt;
            if (!shared || !pub) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.u64(p->kdf).bytes(*shared).bytes(*pub);
            return CKR_OK;
        }
        case param_kind::hkdf: {
            const auto* p = param_of<CK_HKDF_PARAMS>(m);
            const auto salt = p != nullptr ? caller_span(p->pSalt, p->ulSaltLen) : std::nullopt;
            const auto info = p != nullptr ? caller_span(p->pInfo, p->ulInfoLen) : std::nullopt;
            if (!salt || !info) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            w.u64(m.mechanism).u8(static_cast<std::uint8_t>(kind));
            w.u8(p->bExtract != CK_FALSE ? 1 : 0).u8(p->bExpand != CK_FALSE ? 1 : 0);
            w.u64(p->prfHashMechanism).u64(p->ulSaltType).bytes(*salt).u64(p->hSaltKey);
            w.bytes(*info);
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_PARAM_INVALID;
}

/// A mechanism read off the wire, its parameter structure rebuilt around
/// buffers this object owns. It cannot move, since the structure points
/// into it.
class mechanism_params {
public:
    mechanism_params() = default;
    mechanism_params(const mechanism_params&) = delete;
    auto operator=(const mechanism_params&) -> mechanism_params& = delete;
    mechanism_params(mechanism_params&&) = delete;
    auto operator=(mechanism_params&&) -> mechanism_params& = delete;
    ~mechanism_params() {
        wipe(_a);
        wipe(_b);
    }

    /// Reads what put_mechanism wrote. CKR_MECHANISM_PARAM_INVALID when the
    /// kind is not the one the mechanism's parameter has (so a structure
    /// with pointers never arrives as raw bytes) or is unknown; throws
    /// std::invalid_argument when the bytes run short.
    auto read(byte_reader& r) -> CK_RV {
        _m.mechanism = static_cast<CK_MECHANISM_TYPE>(r.u64());
        const auto kind = static_cast<param_kind>(r.u8());
        if (kind == param_kind::none) {
            return CKR_OK;
        }
        if (kind != param_kind_of(_m.mechanism)) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        switch (kind) {
            case param_kind::none:
                return CKR_OK;
            case param_kind::raw:
                _a = r.bytes();
                point(data(_a), _a.size());
                return CKR_OK;
            case param_kind::gcm:
                _a = r.bytes();
                _gcm.ulIvBits = static_cast<CK_ULONG>(r.u64());
                _b = r.bytes();
                _gcm.ulTagBits = static_cast<CK_ULONG>(r.u64());
                _gcm.pIv = data(_a);
                _gcm.ulIvLen = static_cast<CK_ULONG>(_a.size());
                _gcm.pAAD = data(_b);
                _gcm.ulAADLen = static_cast<CK_ULONG>(_b.size());
                point(&_gcm, sizeof _gcm);
                return CKR_OK;
            case param_kind::oaep:
                _oaep.hashAlg = static_cast<CK_MECHANISM_TYPE>(r.u64());
                _oaep.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(r.u64());
                _oaep.source = static_cast<CK_RSA_PKCS_OAEP_SOURCE_TYPE>(r.u64());
                _a = r.bytes();
                _oaep.pSourceData = data(_a);
                _oaep.ulSourceDataLen = static_cast<CK_ULONG>(_a.size());
                point(&_oaep, sizeof _oaep);
                return CKR_OK;
            case param_kind::pss:
                _pss.hashAlg = static_cast<CK_MECHANISM_TYPE>(r.u64());
                _pss.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(r.u64());
                _pss.sLen = static_cast<CK_ULONG>(r.u64());
                point(&_pss, sizeof _pss);
                return CKR_OK;
            case param_kind::eddsa:
                _eddsa.phFlag = r.u8() != 0 ? CK_TRUE : CK_FALSE;
                _a = r.bytes();
                _eddsa.pContextData = data(_a);
                _eddsa.ulContextDataLen = static_cast<CK_ULONG>(_a.size());
                point(&_eddsa, sizeof _eddsa);
                return CKR_OK;
            case param_kind::ecdh1:
                _ecdh.kdf = static_cast<CK_EC_KDF_TYPE>(r.u64());
                _a = r.bytes();
                _b = r.bytes();
                _ecdh.pSharedData = data(_a);
                _ecdh.ulSharedDataLen = static_cast<CK_ULONG>(_a.size());
                _ecdh.pPublicData = data(_b);
                _ecdh.ulPublicDataLen = static_cast<CK_ULONG>(_b.size());
                point(&_ecdh, sizeof _ecdh);
                return CKR_OK;
            case param_kind::hkdf:
                _hkdf.bExtract = r.u8() != 0 ? CK_TRUE : CK_FALSE;
                _hkdf.bExpand = r.u8() != 0 ? CK_TRUE : CK_FALSE;
                _hkdf.prfHashMechanism = static_cast<CK_MECHANISM_TYPE>(r.u64());
                _hkdf.ulSaltType = static_cast<CK_ULONG>(r.u64());
                _a = r.bytes();
                _hkdf.hSaltKey = static_cast<CK_OBJECT_HANDLE>(r.u64());
                _b = r.bytes();
                _hkdf.pSalt = data(_a);
                _hkdf.ulSaltLen = static_cast<CK_ULONG>(_a.size());
                _hkdf.pInfo = data(_b);
                _hkdf.ulInfoLen = static_cast<CK_ULONG>(_b.size());
                point(&_hkdf, sizeof _hkdf);
                return CKR_OK;
        }
        return CKR_MECHANISM_PARAM_INVALID;
    }

    [[nodiscard]] auto get() const noexcept -> const CK_MECHANISM& { return _m; }

private:
    static auto data(std::vector<std::uint8_t>& v) -> CK_BYTE_PTR {
        return v.empty() ? nullptr : v.data();
    }
    void point(void* p, std::size_t n) {
        _m.pParameter = p;
        _m.ulParameterLen = static_cast<CK_ULONG>(n);
    }

    CK_MECHANISM _m{0, nullptr, 0};
    std::vector<std::uint8_t> _a;
    std::vector<std::uint8_t> _b;
    CK_GCM_PARAMS _gcm{};
    CK_RSA_PKCS_OAEP_PARAMS _oaep{};
    CK_RSA_PKCS_PSS_PARAMS _pss{};
    CK_EDDSA_PARAMS _eddsa{};
    CK_ECDH1_DERIVE_PARAMS _ecdh{};
    CK_HKDF_PARAMS _hkdf{};
};

}  // namespace kythira::hsm::wire
