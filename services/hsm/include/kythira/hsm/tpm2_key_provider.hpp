// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A `kms_key_provider` over a TPM 2.0 (.kiro/specs/virtual-hsm/ task 8b,
// requirement 4.4), so that `kms_share_sealer` can seal a node-unseal share
// to the machine's TPM: the share's data key then opens only on that TPM,
// and, with a PCR policy, only while the machine booted as it did when the
// share was sealed. Built with tpm2-tss's ESAPI (libtss2-esys,
// libtss2-tctildr, libtss2-mu, libtss2-rc), only when CMake finds them
// (KYTHIRA_HSM_TPM2).
//
// The key id names the parent the data key is sealed under: "owner" (the
// default) for a primary storage key derived again on every call from the
// owner hierarchy's seed with the TCG's ECC P-256 storage key template, so
// nothing has to be provisioned (the owner hierarchy's auth must be empty);
// or a persistent handle ("0x81000001") the operator made, whose auth must
// be empty.
//
// A data key is 32 random bytes from this process, sealed as a keyed-hash
// object's sensitive data together with SHA-256 of the encryption
// context's binding (raft/kms_key_provider_cloud.hpp), checked on unseal.
// The object is fixedTPM and fixedParent: its private part, which is what
// is stored, opens nowhere but under that parent on that TPM. Create and
// Unseal run in a session salted to the parent, with parameter encryption,
// so the data key never crosses the TPM bus in the clear.
//
// With PCRs configured ("sha256:0,2,4,7"), the object's auth policy is
// PolicyPCR over those PCRs' values at seal time, and the selection is
// stored with the sealed key (a bank the TPM has not allocated is refused:
// a policy over it would bind nothing); a PCR that has moved since (another
// firmware, boot loader or kernel) fails the unseal with `access_denied`,
// and the member collects its share from its peers instead.
//
// Errors map onto `kms_failure`: a TCTI that cannot reach the TPM to
// `unavailable`, a policy or auth failure to `access_denied`, the TPM's
// dictionary-attack lockout to `throttling`, anything else (a blob from
// another TPM, a malformed one) to `invalid_state`.
//
// The wrapped key is
//
//   "KTP1" | u8 PCR spec length | PCR spec | u16 public length | TPM2B_PUBLIC |
//   u16 private length | TPM2B_PRIVATE
//
// One ESAPI context serves the provider, behind a mutex: TPM calls are
// serial anyway. A call that loses the TCTI drops the context, and the
// next call opens it again.

#include <raft/kms_key_provider.hpp>
#include <raft/kms_key_provider_cloud.hpp>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <bit>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

struct tpm2_config {
    /// tpm2-tss's TCTI: "device:/dev/tpmrm0" (the kernel's resource
    /// manager, the default), "tabrmd:", "swtpm:host=...,port=..." and so
    /// on.
    std::string tcti = "device:/dev/tpmrm0";
    /// PCRs a new seal is bound to, "sha256:0,2,4,7" or "sha1:..."; empty
    /// binds none.
    std::string pcrs;
};

namespace tpm2_detail {

inline constexpr std::string_view k_magic = "KTP1";

[[nodiscard]] inline auto failure_of(TSS2_RC rc) -> kms_provider::kms_failure {
    namespace kp = kms_provider;
    if ((rc & TSS2_RC_LAYER_MASK) == TSS2_TCTI_RC_LAYER) {
        return kp::kms_failure::unavailable;
    }
    // Format-one codes carry the parameter, handle or session number in
    // their upper bits; the error itself is the low bits.
    const auto base = (rc & TPM2_RC_FMT1) != 0U ? (rc & (TPM2_RC_FMT1 | 0x3FU)) : (rc & 0xFFFU);
    if (base == TPM2_RC_POLICY_FAIL || base == TPM2_RC_AUTH_FAIL || base == TPM2_RC_BAD_AUTH ||
        base == TPM2_RC_PCR_CHANGED || base == TPM2_RC_POLICY) {
        return kp::kms_failure::access_denied;
    }
    if (base == TPM2_RC_LOCKOUT) {
        return kp::kms_failure::throttling;
    }
    return kp::kms_failure::invalid_state;
}

[[noreturn]] inline void raise(std::string_view what, TSS2_RC rc) {
    throw kms_provider::kms_error(failure_of(rc),
                                  "TPM " + std::string(what) + ": " + Tss2_RC_Decode(rc));
}

inline void check(std::string_view what, TSS2_RC rc) {
    if (rc != TSS2_RC_SUCCESS) {
        raise(what, rc);
    }
}

/// "sha256:0,2,4,7" as a selection; throws std::invalid_argument.
[[nodiscard]] inline auto parse_pcrs(std::string_view spec) -> TPML_PCR_SELECTION {
    TPML_PCR_SELECTION out{};
    if (spec.empty()) {
        return out;
    }
    const auto colon = spec.find(':');
    const auto bank = spec.substr(0, colon);
    TPMI_ALG_HASH alg = TPM2_ALG_NULL;
    if (bank == "sha256") {
        alg = TPM2_ALG_SHA256;
    } else if (bank == "sha1") {
        alg = TPM2_ALG_SHA1;
    } else if (bank == "sha384") {
        alg = TPM2_ALG_SHA384;
    }
    if (alg == TPM2_ALG_NULL || colon == std::string_view::npos || colon + 1 == spec.size()) {
        throw std::invalid_argument("a PCR selection is <sha1|sha256|sha384>:<n>[,<n>...]: " +
                                    std::string(spec));
    }
    out.count = 1;
    auto& sel = out.pcrSelections[0];
    sel.hash = alg;
    sel.sizeofSelect = 3;
    auto rest = spec.substr(colon + 1);
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        const auto item = rest.substr(0, comma);
        unsigned n = 0;
        const auto [end, ec] = std::from_chars(item.data(), item.data() + item.size(), n);
        if (ec != std::errc{} || end != item.data() + item.size() || n > 23) {
            throw std::invalid_argument("a PCR is 0-23: " + std::string(spec));
        }
        sel.pcrSelect[n / 8] |= static_cast<BYTE>(1U << (n % 8));
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
    }
    return out;
}

/// Refuses a selection the TPM does not have: PolicyPCR over a bank that
/// is not allocated selects nothing, and the seal would bind no PCR at
/// all.
inline void require_banks(ESYS_CONTEXT* ctx, const TPML_PCR_SELECTION& pcrs,
                          std::string_view spec) {
    UINT32 counter = 0;
    TPML_PCR_SELECTION* got = nullptr;
    TPML_DIGEST* values = nullptr;
    check("PCR_Read", Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pcrs, &counter,
                                    &got, &values));
    std::size_t wanted = 0;
    for (const auto b : pcrs.pcrSelections[0].pcrSelect) {
        wanted += static_cast<std::size_t>(std::popcount(static_cast<unsigned>(b)));
    }
    const bool all =
        got->count == 1 && got->pcrSelections[0].hash == pcrs.pcrSelections[0].hash &&
        std::memcmp(got->pcrSelections[0].pcrSelect, pcrs.pcrSelections[0].pcrSelect, 3) == 0 &&
        values->count == wanted;
    Esys_Free(got);
    Esys_Free(values);
    if (!all) {
        throw kms_provider::kms_error(kms_provider::kms_failure::invalid_state,
                                      "The TPM has no such PCRs allocated: " + std::string(spec));
    }
}

[[nodiscard]] inline auto digest(std::string_view in) -> std::array<unsigned char, 32> {
    std::array<unsigned char, 32> out{};
    unsigned int n = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha256(), nullptr) != 1) {
        throw kms_provider::kms_error(kms_provider::kms_failure::invalid_state, "SHA-256 failed.");
    }
    return out;
}

/// The TCG storage key template (ECC P-256, AES-128-CFB).
[[nodiscard]] inline auto storage_key_template() -> TPM2B_PUBLIC {
    TPM2B_PUBLIC t{};
    auto& p = t.publicArea;
    p.type = TPM2_ALG_ECC;
    p.nameAlg = TPM2_ALG_SHA256;
    p.objectAttributes = TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                         TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                         TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_NODA;
    p.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    p.parameters.eccDetail.symmetric.keyBits.aes = 128;
    p.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    p.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    p.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    p.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    p.unique.ecc.x.size = 32;
    p.unique.ecc.y.size = 32;
    return t;
}

[[nodiscard]] inline auto parse_handle(std::string_view key_id) -> std::optional<TPM2_HANDLE> {
    if (!key_id.starts_with("0x") || key_id.size() != 10) {
        return std::nullopt;
    }
    std::uint32_t h = 0;
    const auto [end, ec] = std::from_chars(key_id.data() + 2, key_id.data() + key_id.size(), h, 16);
    if (ec != std::errc{} || end != key_id.data() + key_id.size() ||
        (h & 0xFF000000U) != TPM2_HR_PERSISTENT) {
        return std::nullopt;
    }
    return h;
}

}  // namespace tpm2_detail

class tpm2_key_provider {
public:
    explicit tpm2_key_provider(tpm2_config config)
        : _state(std::make_shared<state>(std::move(config))) {
        // A bad selection fails here, at startup, not at the first seal.
        (void)tpm2_detail::parse_pcrs(_state->config.pcrs);
    }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const kms_provider::encryption_context& context) const
        -> kms_provider::generated_data_key {
        namespace kp = kms_provider;
        kp::data_key_bytes plain{};
        if (RAND_bytes(plain.data(), static_cast<int>(plain.size())) != 1) {
            throw kp::kms_error(kp::kms_failure::unavailable, "No random bytes for a data key.");
        }
        auto out = wrap_data_key(key_id, plain, context);
        OPENSSL_cleanse(plain.data(), plain.size());
        return out;
    }

    [[nodiscard]] auto wrap_data_key(const std::string& key_id,
                                     const kms_provider::data_key_bytes& plaintext,
                                     const kms_provider::encryption_context& context) const
        -> kms_provider::generated_data_key {
        namespace d = tpm2_detail;
        const auto bound = d::digest(kms_provider::cloud_detail::context_binding(context));
        TPM2B_SENSITIVE_CREATE sensitive{};
        auto& data = sensitive.sensitive.data;
        static_assert(sizeof(data.buffer) >= 64);
        std::memcpy(data.buffer, plaintext.data(), plaintext.size());
        std::memcpy(data.buffer + plaintext.size(), bound.data(), bound.size());
        data.size = static_cast<UINT16>(plaintext.size() + bound.size());
        const std::string pcr_spec = _state->config.pcrs;
        const auto pcrs = d::parse_pcrs(pcr_spec);

        std::vector<std::uint8_t> pub_bytes(sizeof(TPM2B_PUBLIC));
        std::vector<std::uint8_t> priv_bytes(sizeof(TPM2B_PRIVATE));
        std::size_t pub_len = 0;
        std::size_t priv_len = 0;
        try {
            run([&](ESYS_CONTEXT* ctx, scope& s) {
                const auto parent = s.parent(ctx, key_id);
                TPM2B_PUBLIC tmpl{};
                auto& p = tmpl.publicArea;
                p.type = TPM2_ALG_KEYEDHASH;
                p.nameAlg = TPM2_ALG_SHA256;
                p.objectAttributes =
                    TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;
                p.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
                if (pcrs.count == 0) {
                    p.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
                } else {
                    d::require_banks(ctx, pcrs, pcr_spec);
                    const auto trial = s.session(ctx, parent, TPM2_SE_TRIAL);
                    d::check("PolicyPCR", Esys_PolicyPCR(ctx, trial, ESYS_TR_NONE, ESYS_TR_NONE,
                                                         ESYS_TR_NONE, nullptr, &pcrs));
                    TPM2B_DIGEST* policy = nullptr;
                    d::check("PolicyGetDigest",
                             Esys_PolicyGetDigest(ctx, trial, ESYS_TR_NONE, ESYS_TR_NONE,
                                                  ESYS_TR_NONE, &policy));
                    p.authPolicy = *policy;
                    Esys_Free(policy);
                }
                const auto hmac = s.session(ctx, parent, TPM2_SE_HMAC, true);
                const TPM2B_DATA outside{};
                const TPML_PCR_SELECTION creation{};
                TPM2B_PRIVATE* out_priv = nullptr;
                TPM2B_PUBLIC* out_pub = nullptr;
                const auto rc = Esys_Create(ctx, parent, hmac, ESYS_TR_NONE, ESYS_TR_NONE,
                                            &sensitive, &tmpl, &outside, &creation, &out_priv,
                                            &out_pub, nullptr, nullptr, nullptr);
                OPENSSL_cleanse(&sensitive, sizeof(sensitive));
                d::check("Create", rc);
                const auto rc_pub = Tss2_MU_TPM2B_PUBLIC_Marshal(out_pub, pub_bytes.data(),
                                                                 pub_bytes.size(), &pub_len);
                const auto rc_priv = Tss2_MU_TPM2B_PRIVATE_Marshal(out_priv, priv_bytes.data(),
                                                                   priv_bytes.size(), &priv_len);
                Esys_Free(out_pub);
                Esys_Free(out_priv);
                d::check("marshal", rc_pub != TSS2_RC_SUCCESS ? rc_pub : rc_priv);
            });
        } catch (...) {
            OPENSSL_cleanse(&sensitive, sizeof(sensitive));
            throw;
        }
        kms_provider::generated_data_key out;
        out._plaintext = plaintext;
        out._key_id = key_id;
        out._wrapped.assign(d::k_magic);
        out._wrapped.push_back(static_cast<char>(pcr_spec.size()));
        out._wrapped += pcr_spec;
        const auto put = [&out](const std::vector<std::uint8_t>& b, std::size_t n) {
            out._wrapped.push_back(static_cast<char>((n >> 8U) & 0xFFU));
            out._wrapped.push_back(static_cast<char>(n & 0xFFU));
            out._wrapped.append(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
        };
        put(pub_bytes, pub_len);
        put(priv_bytes, priv_len);
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const kms_provider::encryption_context& context) const
        -> kms_provider::data_key_bytes {
        namespace d = tpm2_detail;
        namespace kp = kms_provider;
        const auto malformed = [] {
            return kp::kms_error(kp::kms_failure::invalid_state,
                                 "A malformed TPM-sealed data key.");
        };
        const auto* in = reinterpret_cast<const std::uint8_t*>(wrapped.data());
        std::size_t at = d::k_magic.size();
        if (wrapped.size() < at + 1 || !wrapped.starts_with(d::k_magic)) {
            throw malformed();
        }
        const std::size_t spec_len = in[at++];
        if (wrapped.size() - at < spec_len) {
            throw malformed();
        }
        const auto pcr_spec = wrapped.substr(at, spec_len);
        at += spec_len;
        TPML_PCR_SELECTION pcrs{};
        try {
            pcrs = d::parse_pcrs(pcr_spec);
        } catch (const std::invalid_argument&) {
            throw malformed();
        }
        const auto take = [&](auto& dest, auto unmarshal) {
            if (wrapped.size() - at < 2) {
                throw malformed();
            }
            const std::size_t n = (std::size_t{in[at]} << 8U) | in[at + 1];
            at += 2;
            std::size_t off = 0;
            if (wrapped.size() - at < n || unmarshal(in + at, n, &off, &dest) != TSS2_RC_SUCCESS ||
                off != n) {
                throw malformed();
            }
            at += n;
        };
        TPM2B_PUBLIC pub{};
        TPM2B_PRIVATE priv{};
        take(pub, Tss2_MU_TPM2B_PUBLIC_Unmarshal);
        take(priv, Tss2_MU_TPM2B_PRIVATE_Unmarshal);
        if (at != wrapped.size()) {
            throw malformed();
        }

        kp::data_key_bytes out{};
        bool ok = false;
        run([&](ESYS_CONTEXT* ctx, scope& s) {
            const auto parent = s.parent(ctx, key_id);
            ESYS_TR object = ESYS_TR_NONE;
            d::check("Load", Esys_Load(ctx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &priv, &pub, &object));
            s.own(object);
            ESYS_TR auth = ESYS_TR_NONE;
            if (pcrs.count == 0) {
                auth = s.session(ctx, parent, TPM2_SE_HMAC);
            } else {
                auth = s.session(ctx, parent, TPM2_SE_POLICY);
                d::check("PolicyPCR", Esys_PolicyPCR(ctx, auth, ESYS_TR_NONE, ESYS_TR_NONE,
                                                     ESYS_TR_NONE, nullptr, &pcrs));
            }
            TPM2B_SENSITIVE_DATA* data = nullptr;
            d::check("Unseal", Esys_Unseal(ctx, object, auth, ESYS_TR_NONE, ESYS_TR_NONE, &data));
            const auto bound = d::digest(kp::cloud_detail::context_binding(context));
            ok = data->size == out.size() + bound.size() &&
                 CRYPTO_memcmp(data->buffer + out.size(), bound.data(), bound.size()) == 0;
            if (ok) {
                std::memcpy(out.data(), data->buffer, out.size());
            }
            OPENSSL_cleanse(data, sizeof(*data));
            Esys_Free(data);
        });
        if (!ok) {
            throw kp::kms_error(kp::kms_failure::invalid_state,
                                "The data key was sealed for another encryption context.");
        }
        return out;
    }

    /// Runs `f(ESYS_CONTEXT*)` under the provider's lock, on its context:
    /// for tools and tests (extending a PCR, reading one).
    template<typename F> auto with_esys(F&& f) const {
        const std::scoped_lock lock(_state->mutex);
        return std::forward<F>(f)(_state->open());
    }

private:
    struct state {
        explicit state(tpm2_config c) : config(std::move(c)) {}
        state(const state&) = delete;
        state(state&&) = delete;
        auto operator=(const state&) -> state& = delete;
        auto operator=(state&&) -> state& = delete;
        ~state() { close(); }

        tpm2_config config;
        std::mutex mutex;
        TSS2_TCTI_CONTEXT* tcti = nullptr;
        ESYS_CONTEXT* esys = nullptr;

        auto open() -> ESYS_CONTEXT* {
            if (esys != nullptr) {
                return esys;
            }
            tpm2_detail::check("TCTI " + config.tcti,
                               Tss2_TctiLdr_Initialize(config.tcti.c_str(), &tcti));
            if (const auto rc = Esys_Initialize(&esys, tcti, nullptr); rc != TSS2_RC_SUCCESS) {
                close();
                tpm2_detail::raise("ESAPI", rc);
            }
            // A simulator starts cold; a booted TPM answers that it is
            // initialized already.
            (void)Esys_Startup(esys, TPM2_SU_CLEAR);
            return esys;
        }

        void close() noexcept {
            if (esys != nullptr) {
                Esys_Finalize(&esys);
            }
            if (tcti != nullptr) {
                Tss2_TctiLdr_Finalize(&tcti);
            }
        }
    };

    /// The transient handles one call made, flushed when it ends.
    struct scope {
        ESYS_CONTEXT* ctx = nullptr;
        std::vector<ESYS_TR> owned;

        scope() = default;
        scope(const scope&) = delete;
        scope(scope&&) = delete;
        auto operator=(const scope&) -> scope& = delete;
        auto operator=(scope&&) -> scope& = delete;
        std::vector<ESYS_TR> persistent;

        ~scope() {
            for (const auto h : std::views::reverse(owned)) {
                (void)Esys_FlushContext(ctx, h);
            }
            for (auto h : persistent) {
                (void)Esys_TR_Close(ctx, &h);
            }
        }

        void own(ESYS_TR h) { owned.push_back(h); }

        auto parent(ESYS_CONTEXT* c, const std::string& key_id) -> ESYS_TR {
            namespace kp = kms_provider;
            if (key_id == "owner") {
                const TPM2B_SENSITIVE_CREATE none{};
                const auto tmpl = tpm2_detail::storage_key_template();
                const TPM2B_DATA outside{};
                const TPML_PCR_SELECTION creation{};
                ESYS_TR h = ESYS_TR_NONE;
                tpm2_detail::check(
                    "CreatePrimary",
                    Esys_CreatePrimary(c, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                       ESYS_TR_NONE, &none, &tmpl, &outside, &creation, &h, nullptr,
                                       nullptr, nullptr, nullptr));
                own(h);
                return h;
            }
            const auto handle = tpm2_detail::parse_handle(key_id);
            if (!handle) {
                throw kp::kms_error(kp::kms_failure::not_found,
                                    "A TPM key id is \"owner\" or a persistent handle "
                                    "(0x81xxxxxx): " +
                                        key_id);
            }
            ESYS_TR h = ESYS_TR_NONE;
            const auto rc =
                Esys_TR_FromTPMPublic(c, *handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &h);
            if (rc != TSS2_RC_SUCCESS) {
                throw kp::kms_error((rc & TSS2_RC_LAYER_MASK) == TSS2_TCTI_RC_LAYER
                                        ? kp::kms_failure::unavailable
                                        : kp::kms_failure::not_found,
                                    "TPM handle " + key_id + ": " + Tss2_RC_Decode(rc));
            }
            persistent.push_back(h);
            return h;
        }

        /// A session salted to `salt_key`, of the given type, encrypting
        /// the command's first parameter (`decrypt`, for Create's
        /// sensitive data) and the response's (for Unseal's data).
        auto session(ESYS_CONTEXT* c, ESYS_TR salt_key, TPM2_SE type, bool decrypt = false)
            -> ESYS_TR {
            TPMT_SYM_DEF sym{};
            sym.algorithm = TPM2_ALG_AES;
            sym.keyBits.aes = 128;
            sym.mode.aes = TPM2_ALG_CFB;
            ESYS_TR h = ESYS_TR_NONE;
            tpm2_detail::check(
                "StartAuthSession",
                Esys_StartAuthSession(c, salt_key, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                      ESYS_TR_NONE, nullptr, type, &sym, TPM2_ALG_SHA256, &h));
            own(h);
            if (type != TPM2_SE_TRIAL) {
                tpm2_detail::check("session attributes",
                                   Esys_TRSess_SetAttributes(c, h,
                                                             (decrypt ? TPMA_SESSION_DECRYPT : 0U) |
                                                                 TPMA_SESSION_ENCRYPT |
                                                                 TPMA_SESSION_CONTINUESESSION,
                                                             0xFF));
            }
            return h;
        }
    };

    template<typename F> void run(F&& f) const {
        const std::scoped_lock lock(_state->mutex);
        auto* ctx = _state->open();
        try {
            scope s;
            s.ctx = ctx;
            std::forward<F>(f)(ctx, s);
        } catch (const kms_provider::kms_error& e) {
            if (e.failure() == kms_provider::kms_failure::unavailable) {
                _state->close();
            }
            throw;
        }
    }

    std::shared_ptr<state> _state;
};

static_assert(kms_provider::kms_key_provider<tpm2_key_provider>);
static_assert(kms_provider::wrapping_kms_key_provider<tpm2_key_provider>);

}  // namespace kythira::hsm
