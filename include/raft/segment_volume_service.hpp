// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file segment_volume_service.hpp
/// @brief A segment node's volumes and the volume API a data node writes
///        its record segments through (.kiro/specs/kinesis-independent-layers/
///        task 9, design "Segment store as a layer", Requirements 9.1-9.3,
///        9.6 and 9.7).
///
/// A data replica whose record bytes live on a separate segment node holds
/// a `remote_segment_store` (`remote_segment_store.hpp`); the segment node
/// runs this service. Each replica gets its own *volume*: one ordinary
/// `record_segment_store` under `<data_dir>/volumes/<volume id>/`, so the
/// bytes on disk are exactly what a local store would write, and moving a
/// segment between local and remote is a file copy (Requirement 9.7).
///
/// ```
/// <data_dir>/volumes/<volume id>/EPOCH          writer epoch, decimal
/// <data_dir>/volumes/<volume id>/streams/...    record_segment_store layout
/// <data_dir>/volumes/<volume id>/tmp/
/// ```
///
/// ## Writer fencing
///
/// A volume belongs to one replica at a time, named by its *epoch*. The
/// assignment (task 10, from the catalog) calls `assign(volume, epoch)`;
/// every write carries the writer's epoch and is refused unless it equals
/// the volume's, so a replica that was replaced while partitioned cannot
/// write into its successor's files (it gets `stale_epoch` and stops).
/// Barriers are writes too: a fenced replica must not acknowledge entries.
/// Reads are not fenced; segment bytes carry their own SHA-256.
///
/// ## Wire format
///
/// `handle()` takes one request and returns one response, both a CBOR
/// array (RFC 8949: unsigned integers, byte and text strings, arrays,
/// booleans and null only). A request is `[op, volume, epoch, args...]`; a
/// response is `[status, results...]`, or `[status, message]` when the
/// status is not `ok`. Timestamps travel as the unsigned bit pattern of the
/// signed value. Segment descriptors travel as the store's own descriptor
/// encoding (`encode_segment_descriptor`) in a byte string. The transport
/// is the caller's: the node serves `handle()` on its internal listener
/// behind the layer route guard (volume calls need the `data` role).

#include <raft/record_segment_store.hpp>
#include <raft/segment_store.hpp>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace kythira {

/// A write refused because the writer's epoch is not the volume's: the
/// replica has been replaced and must stop applying.
class segment_volume_fenced : public record_segment_error {
public:
    using record_segment_error::record_segment_error;
};

namespace volume_wire {

enum class op : std::uint8_t {
    append = 1,
    barrier = 2,
    seal = 3,
    truncate_after = 4,
    trim_before = 5,
    remove_segment = 6,
    drop_stream = 7,
    install_segment = 8,
    read_segment_bytes = 9,
    read_segment = 10,
    read = 11,
    describe = 12,
    local_segments = 13,
    has_segment = 14,
    last_seq = 15,
    streams = 16,
    stats = 17,
    max_record_bytes = 18,
    /// The segment node's own storage, not a volume's: `[capacity,
    /// available]` in bytes (task 10, Requirement 10.6). The volume and
    /// epoch are ignored.
    space = 19,
    /// Gives the volume to the writer at the request's epoch, creating it
    /// if needed (task 10). An epoch older than the volume's is refused
    /// (`invalid_argument`); the same epoch again is a no-op. The epoch
    /// comes from the volume assignment in the catalog, so a replica moved
    /// to a segment node that never heard of its volume can open it there,
    /// and a segment node needs no Raft of its own.
    assign = 20,
};

/// Whether `o` changes the volume, and so is fenced by epoch.
[[nodiscard]] constexpr auto is_write(op o) noexcept -> bool {
    switch (o) {
        case op::append:
        case op::barrier:
        case op::seal:
        case op::truncate_after:
        case op::trim_before:
        case op::remove_segment:
        case op::drop_stream:
        case op::install_segment:
            return true;
        default:
            return false;
    }
}

enum class status : std::uint8_t {
    ok = 0,
    /// The writer's epoch is not the volume's.
    stale_epoch = 1,
    /// No such volume on this node.
    unknown_volume = 2,
    /// The request or its arguments were refused (a malformed request, an
    /// install whose bytes do not match the descriptor, ...).
    invalid_argument = 3,
    /// The store failed (an I/O error).
    failed = 4,
};

/// Writes the CBOR subset the volume API uses.
class writer {
public:
    void uint(std::uint64_t v) { head(0, v); }
    void bytes(std::span<const std::byte> b) {
        head(2, b.size());
        _out.insert(_out.end(), b.begin(), b.end());
    }
    void text(std::string_view s) {
        head(3, s.size());
        for (const char c : s) {
            _out.push_back(static_cast<std::byte>(c));
        }
    }
    void array(std::size_t n) { head(4, n); }
    void boolean(bool b) { _out.push_back(static_cast<std::byte>(b ? 0xF5 : 0xF4)); }
    void null() { _out.push_back(std::byte{0xF6}); }
    void descriptor(const record_segment_descriptor& d) { bytes(encode_segment_descriptor(d)); }

    [[nodiscard]] auto take() -> std::vector<std::byte> { return std::move(_out); }

private:
    void head(std::uint8_t major, std::uint64_t v) {
        const auto m = static_cast<std::uint8_t>(major << 5U);
        if (v < 24) {
            _out.push_back(static_cast<std::byte>(m | v));
            return;
        }
        int n = 8;
        std::uint8_t info = 27;
        if (v <= 0xFFU) {
            n = 1;
            info = 24;
        } else if (v <= 0xFFFFU) {
            n = 2;
            info = 25;
        } else if (v <= 0xFFFFFFFFU) {
            n = 4;
            info = 26;
        }
        _out.push_back(static_cast<std::byte>(m | info));
        for (int i = n - 1; i >= 0; --i) {
            _out.push_back(static_cast<std::byte>((v >> (8U * static_cast<unsigned>(i))) & 0xFFU));
        }
    }

    std::vector<std::byte> _out;
};

/// Reads what `writer` writes. Throws `std::invalid_argument` on anything
/// else, never reading past the input.
class reader {
public:
    explicit reader(std::span<const std::byte> in) : _in(in) {}

    [[nodiscard]] auto uint() -> std::uint64_t { return head(0); }
    [[nodiscard]] auto bytes() -> std::vector<std::byte> {
        const auto n = length(2);
        std::vector<std::byte> out(_in.begin() + static_cast<std::ptrdiff_t>(_at),
                                   _in.begin() + static_cast<std::ptrdiff_t>(_at + n));
        _at += n;
        return out;
    }
    [[nodiscard]] auto text() -> std::string {
        const auto n = length(3);
        std::string out(reinterpret_cast<const char*>(_in.data() + _at), n);
        _at += n;
        return out;
    }
    [[nodiscard]] auto array() -> std::size_t {
        const auto n = head(4);
        // Every element takes at least one byte: a count beyond what is
        // left is garbage, and reserving for it would be a free allocation.
        if (n > _in.size() - _at) {
            throw std::invalid_argument("volume wire: array longer than the message");
        }
        return static_cast<std::size_t>(n);
    }
    [[nodiscard]] auto boolean() -> bool {
        const auto b = next();
        if (b == 0xF5) {
            return true;
        }
        if (b == 0xF4) {
            return false;
        }
        throw std::invalid_argument("volume wire: expected a boolean");
    }
    /// Consumes a null and returns true, or returns false and consumes
    /// nothing.
    [[nodiscard]] auto null() -> bool {
        if (_at < _in.size() && static_cast<std::uint8_t>(_in[_at]) == 0xF6) {
            ++_at;
            return true;
        }
        return false;
    }
    [[nodiscard]] auto descriptor() -> record_segment_descriptor {
        const auto b = bytes();
        std::span<const std::byte> in(b);
        auto d = decode_segment_descriptor(in);
        if (!d || !in.empty()) {
            throw std::invalid_argument("volume wire: bad segment descriptor");
        }
        return *d;
    }
    [[nodiscard]] auto at_end() const noexcept -> bool { return _at == _in.size(); }

private:
    [[nodiscard]] auto next() -> std::uint8_t {
        if (_at >= _in.size()) {
            throw std::invalid_argument("volume wire: message ends early");
        }
        return static_cast<std::uint8_t>(_in[_at++]);
    }
    [[nodiscard]] auto head(std::uint8_t major) -> std::uint64_t {
        const auto b = next();
        if ((b >> 5U) != major) {
            throw std::invalid_argument("volume wire: unexpected item type");
        }
        const std::uint8_t info = b & 0x1FU;
        if (info < 24) {
            return info;
        }
        int n = 0;
        switch (info) {
            case 24:
                n = 1;
                break;
            case 25:
                n = 2;
                break;
            case 26:
                n = 4;
                break;
            case 27:
                n = 8;
                break;
            default:
                throw std::invalid_argument("volume wire: unsupported length encoding");
        }
        std::uint64_t v = 0;
        for (int i = 0; i < n; ++i) {
            v = (v << 8U) | next();
        }
        return v;
    }
    [[nodiscard]] auto length(std::uint8_t major) -> std::size_t {
        const auto n = head(major);
        if (n > _in.size() - _at) {
            throw std::invalid_argument("volume wire: string longer than the message");
        }
        return static_cast<std::size_t>(n);
    }

    std::span<const std::byte> _in;
    std::size_t _at = 0;
};

inline void write_records(writer& w, const std::vector<segment_record>& records) {
    w.array(records.size());
    for (const auto& r : records) {
        w.array(3);
        w.uint(r._seq);
        w.uint(static_cast<std::uint64_t>(r._timestamp_ms));
        w.bytes(r._data);
    }
}

[[nodiscard]] inline auto read_records(reader& r) -> std::vector<segment_record> {
    std::vector<segment_record> out(r.array());
    for (auto& rec : out) {
        if (r.array() != 3) {
            throw std::invalid_argument("volume wire: a record is [seq, ts, data]");
        }
        rec._seq = r.uint();
        rec._timestamp_ms = static_cast<std::int64_t>(r.uint());
        rec._data = r.bytes();
    }
    return out;
}

inline void write_read_result(writer& w, const segment_read_result& res) {
    w.array(3);
    write_records(w, res._records);
    w.uint(res._next_seq);
    w.boolean(res._segment_exhausted);
}

[[nodiscard]] inline auto read_read_result(reader& r) -> segment_read_result {
    if (r.array() != 3) {
        throw std::invalid_argument("volume wire: a read result is [records, next, exhausted]");
    }
    segment_read_result out;
    out._records = read_records(r);
    out._next_seq = r.uint();
    out._segment_exhausted = r.boolean();
    return out;
}

inline void write_stats(writer& w, const record_segment_store_stats& s) {
    w.array(11);
    for (const auto v : {s._streams, s._active_segments, s._sealed_segments, s._bytes_on_disk,
                         s._records_appended, s._barriers, s._torn_tails_truncated, s._quarantined,
                         s._installed, s._fetch_misses, s._read_crc_failures}) {
        w.uint(v);
    }
}

[[nodiscard]] inline auto read_stats(reader& r) -> record_segment_store_stats {
    if (r.array() != 11) {
        throw std::invalid_argument("volume wire: stats has 11 fields");
    }
    record_segment_store_stats s;
    for (auto* f : {&s._streams, &s._active_segments, &s._sealed_segments, &s._bytes_on_disk,
                    &s._records_appended, &s._barriers, &s._torn_tails_truncated, &s._quarantined,
                    &s._installed, &s._fetch_misses, &s._read_crc_failures}) {
        *f = r.uint();
    }
    return s;
}

}  // namespace volume_wire

struct segment_volume_service_options {
    /// The segment node's data directory; volumes go under `volumes/`.
    std::filesystem::path data_dir;
    /// Options for each volume's store. `_data_dir` is replaced by the
    /// volume's directory. Every replica of a group must use the same
    /// segment size and age bounds, local or remote, or their files stop
    /// being byte-identical.
    record_segment_store_options store;
};

/// A segment node's volumes. Thread-safe: `handle` may run on many
/// connection threads at once.
class segment_volume_service {
public:
    /// Opens every volume already under `<data_dir>/volumes/`, each with
    /// the epoch it last had.
    explicit segment_volume_service(segment_volume_service_options options)
        : _options(std::move(options)), _root(_options.data_dir / "volumes") {
        std::filesystem::create_directories(_root);
        for (const auto& entry : std::filesystem::directory_iterator(_root)) {
            if (!entry.is_directory()) {
                continue;
            }
            const auto id = entry.path().filename().string();
            if (!valid_volume_id(id)) {
                continue;
            }
            const auto epoch = read_epoch(entry.path());
            if (!epoch) {
                continue;  // never finished assigning: not a volume yet
            }
            _volumes.emplace(id, volume_state{.store = open_store(entry.path()), .epoch = *epoch});
        }
    }

    /// 1-128 letters, digits, '-', '.' or '_', not starting with '.'.
    [[nodiscard]] static auto valid_volume_id(std::string_view id) noexcept -> bool {
        if (id.empty() || id.size() > 128 || id.front() == '.') {
            return false;
        }
        const auto allowed = [](char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '-' || c == '.' || c == '_';
        };
        for (const char c : id) {
            if (!allowed(c)) {
                return false;
            }
        }
        return true;
    }

    /// Gives `volume` to the writer at `epoch`, creating it if needed.
    /// Refuses an epoch older than the volume's (`std::invalid_argument`).
    /// Durable on return.
    void assign(const std::string& volume, std::uint64_t epoch) {
        if (!valid_volume_id(volume)) {
            throw std::invalid_argument("segment volume: invalid volume id \"" + volume + "\"");
        }
        const std::unique_lock lock(_mu);
        auto it = _volumes.find(volume);
        const auto dir = _root / volume;
        if (it == _volumes.end()) {
            std::filesystem::create_directories(dir);
            write_epoch(dir, epoch);
            _volumes.emplace(volume, volume_state{.store = open_store(dir), .epoch = epoch});
            return;
        }
        if (epoch < it->second.epoch) {
            throw std::invalid_argument("segment volume: epoch " + std::to_string(epoch) +
                                        " is older than volume " + volume + "'s " +
                                        std::to_string(it->second.epoch));
        }
        write_epoch(dir, epoch);
        it->second.epoch = epoch;
    }

    /// Removes a volume and its files.
    void drop(const std::string& volume) {
        const std::unique_lock lock(_mu);
        if (_volumes.erase(volume) != 0) {
            std::filesystem::remove_all(_root / volume);
            (void)detail::segments::fsync_dir(_root);
        }
    }

    /// Every volume and its epoch.
    [[nodiscard]] auto volumes() const -> std::vector<std::pair<std::string, std::uint64_t>> {
        const std::shared_lock lock(_mu);
        std::vector<std::pair<std::string, std::uint64_t>> out;
        for (const auto& [id, v] : _volumes) {
            out.emplace_back(id, v.epoch);
        }
        return out;
    }

    /// A volume's directory, for copying a store in or out (task 13).
    [[nodiscard]] auto volume_dir(const std::string& volume) const -> std::filesystem::path {
        return _root / volume;
    }

    /// Answers one volume API request (see the file comment). Never
    /// throws: every failure is a status.
    [[nodiscard]] auto handle(std::span<const std::byte> request) -> std::vector<std::byte> {
        using volume_wire::status;
        try {
            volume_wire::reader r(request);
            const auto n = r.array();
            if (n < 3) {
                throw std::invalid_argument("volume wire: a request is [op, volume, epoch, ...]");
            }
            const auto o = static_cast<volume_wire::op>(r.uint());
            const auto id = r.text();
            const auto epoch = r.uint();
            if (o == volume_wire::op::space) {
                if (!r.at_end()) {
                    throw std::invalid_argument("volume wire: trailing bytes in the request");
                }
                return space_reply();
            }
            if (o == volume_wire::op::assign) {
                if (!r.at_end()) {
                    throw std::invalid_argument("volume wire: trailing bytes in the request");
                }
                if (epoch == 0) {
                    throw std::invalid_argument("volume wire: a volume's epoch starts at 1");
                }
                assign(id, epoch);
                volume_wire::writer w;
                w.array(1);
                w.uint(static_cast<std::uint64_t>(status::ok));
                return w.take();
            }
            std::shared_ptr<record_segment_store> store;
            {
                const std::shared_lock lock(_mu);
                const auto it = _volumes.find(id);
                if (it == _volumes.end()) {
                    return error(status::unknown_volume, "no volume " + id);
                }
                if (volume_wire::is_write(o) && epoch != it->second.epoch) {
                    return error(status::stale_epoch, "volume " + id + " is at epoch " +
                                                          std::to_string(it->second.epoch) +
                                                          ", not " + std::to_string(epoch));
                }
                store = it->second.store;
            }
            auto out = dispatch(o, *store, r);
            if (!r.at_end()) {
                throw std::invalid_argument("volume wire: trailing bytes in the request");
            }
            return out;
        } catch (const std::invalid_argument& e) {
            return error(status::invalid_argument, e.what());
        } catch (const std::exception& e) {
            return error(status::failed, e.what());
        }
    }

private:
    struct volume_state {
        std::shared_ptr<record_segment_store> store;
        std::uint64_t epoch = 0;
    };

    [[nodiscard]] auto open_store(const std::filesystem::path& dir) const
        -> std::shared_ptr<record_segment_store> {
        auto o = _options.store;
        o._data_dir = dir;
        return std::make_shared<record_segment_store>(o);
    }

    [[nodiscard]] static auto read_epoch(const std::filesystem::path& dir)
        -> std::optional<std::uint64_t> {
        std::ifstream in(dir / "EPOCH");
        std::uint64_t e = 0;
        if (!(in >> e)) {
            return std::nullopt;
        }
        return e;
    }

    /// Writes EPOCH through a temporary file, a rename and fsyncs, so a
    /// crash leaves the old epoch or the new one, never a torn file.
    static void write_epoch(const std::filesystem::path& dir, std::uint64_t epoch) {
        const auto tmp = dir / "EPOCH.tmp";
        const auto text = std::to_string(epoch) + "\n";
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
        if (fd < 0) {
            throw record_segment_error(detail::segments::errno_text("open " + tmp.string()));
        }
        const bool ok =
            ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()) &&
            ::fsync(fd) == 0;
        ::close(fd);
        if (!ok) {
            throw record_segment_error(detail::segments::errno_text("write " + tmp.string()));
        }
        std::filesystem::rename(tmp, dir / "EPOCH");
        if (!detail::segments::fsync_dir(dir)) {
            throw record_segment_error(detail::segments::errno_text("fsync " + dir.string()));
        }
    }

    /// `[ok, capacity, available]` for the filesystem the volumes live on.
    [[nodiscard]] auto space_reply() const -> std::vector<std::byte> {
        const auto info = std::filesystem::space(_root);
        volume_wire::writer w;
        w.array(3);
        w.uint(static_cast<std::uint64_t>(volume_wire::status::ok));
        w.uint(static_cast<std::uint64_t>(info.capacity));
        w.uint(static_cast<std::uint64_t>(info.available));
        return w.take();
    }

    [[nodiscard]] static auto error(volume_wire::status s, std::string_view message)
        -> std::vector<std::byte> {
        volume_wire::writer w;
        w.array(2);
        w.uint(static_cast<std::uint64_t>(s));
        w.text(message);
        return w.take();
    }

    [[nodiscard]] static auto limits_from(volume_wire::reader& r) -> segment_read_limits {
        segment_read_limits l;
        l._max_records = static_cast<std::size_t>(r.uint());
        l._max_bytes = r.uint();
        return l;
    }

    [[nodiscard]] static auto dispatch(volume_wire::op o, record_segment_store& store,
                                       volume_wire::reader& r) -> std::vector<std::byte> {
        using volume_wire::op;
        volume_wire::writer w;
        auto ok = [&w](std::size_t results) {
            w.array(1 + results);
            w.uint(static_cast<std::uint64_t>(volume_wire::status::ok));
        };
        switch (o) {
            case op::append: {
                const auto stream = r.text();
                const auto records = volume_wire::read_records(r);
                std::vector<segment_record_view> views;
                views.reserve(records.size());
                for (const auto& rec : records) {
                    views.push_back({rec._seq, rec._timestamp_ms, rec._data});
                }
                const auto res = store.append(stream, views);
                ok(1);
                w.array(res._sealed.size());
                for (const auto& d : res._sealed) {
                    w.descriptor(d);
                }
                break;
            }
            case op::barrier:
                store.barrier();
                ok(0);
                break;
            case op::seal: {
                const auto d = store.seal(r.text());
                ok(1);
                d ? w.descriptor(*d) : w.null();
                break;
            }
            case op::truncate_after: {
                const auto stream = r.text();
                std::optional<std::uint64_t> seq;
                if (!r.null()) {
                    seq = r.uint();
                }
                store.truncate_after(stream, seq);
                ok(0);
                break;
            }
            case op::trim_before: {
                const auto stream = r.text();
                const auto removed = store.trim_before(stream, r.uint());
                ok(1);
                w.array(removed.size());
                for (const auto s : removed) {
                    w.uint(s);
                }
                break;
            }
            case op::remove_segment: {
                const auto stream = r.text();
                const auto removed = store.remove_segment(stream, r.uint());
                ok(1);
                w.boolean(removed);
                break;
            }
            case op::drop_stream:
                store.drop_stream(r.text());
                ok(0);
                break;
            case op::install_segment: {
                const auto d = r.descriptor();
                const auto bytes = r.bytes();
                const auto installed = store.install_segment(d, bytes);
                ok(1);
                w.boolean(installed);
                break;
            }
            case op::read_segment_bytes: {
                const auto stream = r.text();
                const auto first = r.uint();
                const auto bytes = store.read_segment_bytes(stream, first, r.uint());
                ok(1);
                bytes ? w.bytes(*bytes) : w.null();
                break;
            }
            case op::read_segment: {
                const auto stream = r.text();
                const auto first = r.uint();
                const auto from = r.uint();
                const auto res = store.read_segment(stream, first, from, limits_from(r));
                ok(1);
                res ? volume_wire::write_read_result(w, *res) : w.null();
                break;
            }
            case op::read: {
                const auto stream = r.text();
                const auto from = r.uint();
                const auto res = store.read(stream, from, limits_from(r));
                ok(1);
                volume_wire::write_read_result(w, res);
                break;
            }
            case op::describe: {
                const auto stream = r.text();
                const auto d = store.describe(stream, r.uint());
                ok(1);
                d ? w.descriptor(*d) : w.null();
                break;
            }
            case op::local_segments: {
                const auto segs = store.local_segments(r.text());
                ok(1);
                w.array(segs.size());
                for (const auto& d : segs) {
                    w.descriptor(d);
                }
                break;
            }
            case op::has_segment: {
                const auto has = store.has_segment(r.descriptor());
                ok(1);
                w.boolean(has);
                break;
            }
            case op::last_seq: {
                const auto last = store.last_seq(r.text());
                ok(1);
                last ? w.uint(*last) : w.null();
                break;
            }
            case op::streams: {
                const auto all = store.streams();
                ok(1);
                w.array(all.size());
                for (const auto& s : all) {
                    w.text(s);
                }
                break;
            }
            case op::stats:
                ok(1);
                volume_wire::write_stats(w, store.stats());
                break;
            case op::max_record_bytes:
                ok(1);
                w.uint(store.max_record_bytes());
                break;
            default:
                throw std::invalid_argument("volume wire: unknown operation " +
                                            std::to_string(static_cast<unsigned>(o)));
        }
        return w.take();
    }

    segment_volume_service_options _options;
    std::filesystem::path _root;
    mutable std::shared_mutex _mu;
    std::map<std::string, volume_state> _volumes;
};

}  // namespace kythira
