// obn::signing — RSA-PKCS#1-v1.5 SHA-256 print-command envelope signer.
//
// All RSA operations go through the EVP_PKEY_* API (OpenSSL 3.x default
// provider).  The legacy RSA_new / RSA_free / EVP_PKEY_assign_RSA path is
// intentionally absent; those symbols are deprecated in OpenSSL 3.0 and
// removed in 4.0.
//
// Key loading:
//   PEM_read_bio_PrivateKey  → EVP_PKEY* (handles both PKCS#1 "RSA
//   PRIVATE KEY" headers and PKCS#8 "PRIVATE KEY" headers transparently).
//
// Signing:
//   EVP_DigestSignInit  (SHA-256, RSA)
//   EVP_PKEY_CTX_set_rsa_padding  (RSA_PKCS1_PADDING)
//   EVP_DigestSign  (two-shot: size query then actual sign)

#include "obn/signing.hpp"

#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>   // RSA_PKCS1_PADDING constant — not a deprecated call

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace obn::signing {

namespace {

// ---------------------------------------------------------------------------
// RAII helpers
// ---------------------------------------------------------------------------

struct EvpPkeyDeleter  { void operator()(EVP_PKEY*   p) const { EVP_PKEY_free(p);   } };
struct EvpPkeyCtxDeleter{ void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct BioDeleter      { void operator()(BIO*        p) const { BIO_free_all(p);     } };

using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY,     EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr   = std::unique_ptr<EVP_MD_CTX,   EvpMdCtxDeleter>;
using BioPtr        = std::unique_ptr<BIO,           BioDeleter>;

// ---------------------------------------------------------------------------
// OpenSSL error helpers
// ---------------------------------------------------------------------------

std::string openssl_last_error_string()
{
    unsigned long e = ERR_get_error();
    if (!e) return "(no OpenSSL error queued)";
    char buf[256] = {};
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

// ---------------------------------------------------------------------------
// Key resolution
// ---------------------------------------------------------------------------

std::string slurp_file(const std::string& path)
{
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool looks_like_pem(const std::string& s)
{
    return s.find("-----BEGIN ") != std::string::npos;
}

// Returns the user's BambuStudio config directory (~/.config/BambuStudio,
// %APPDATA%\BambuStudio, or ~/Library/Application Support/BambuStudio).
std::string default_config_dir()
{
#if defined(_WIN32)
    if (const char* a = std::getenv("APPDATA"); a && *a)
        return std::string(a) + "\\BambuStudio";
    return {};
#elif defined(__APPLE__)
    if (const char* h = std::getenv("HOME"); h && *h)
        return std::string(h) + "/Library/Application Support/BambuStudio";
    return {};
#else
    if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x)
        return std::string(x) + "/BambuStudio";
    if (const char* h = std::getenv("HOME"); h && *h)
        return std::string(h) + "/.config/BambuStudio";
    return {};
#endif
}

// Trim leading/trailing whitespace and newlines.
std::string trim(std::string s)
{
    std::size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' ||
                             s[b] == '\n' || s[b] == '\r'))
        ++b;
    s.erase(0, b);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                           s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s;
}

// Resolve the PEM private key text.  Returns empty string when no key is
// found via any of the resolution steps.
std::string resolve_key_pem(const Config& cfg)
{
    // 1. From cfg.private_key_pem_path (inline PEM or file path).
    if (!cfg.private_key_pem_path.empty()) {
        if (looks_like_pem(cfg.private_key_pem_path))
            return cfg.private_key_pem_path;
        std::string text = slurp_file(cfg.private_key_pem_path);
        if (!text.empty()) return text;
        OBN_WARN("signing: cfg.private_key_pem_path='%s' not found",
                 cfg.private_key_pem_path.c_str());
    }

    // 2. From BBL_SLICER_KEY env var (inline PEM or file path).
    if (const char* env = std::getenv("BBL_SLICER_KEY"); env && *env) {
        std::string v(env);
        if (looks_like_pem(v)) return v;
        std::string text = slurp_file(v);
        if (!text.empty()) return text;
        OBN_WARN("signing: BBL_SLICER_KEY='%s' not found", env);
    }

    // 3. From <config_dir>/slicer_key.pem.
    const std::string cdir = default_config_dir();
    if (!cdir.empty()) {
#if defined(_WIN32)
        std::string path = cdir + "\\slicer_key.pem";
#else
        std::string path = cdir + "/slicer_key.pem";
#endif
        std::string text = slurp_file(path);
        if (!text.empty()) return text;
    }

    return {};
}

// Resolve the cert_id string.
std::string resolve_cert_id(const Config& cfg)
{
    if (!cfg.cert_id.empty()) return trim(cfg.cert_id);

    if (const char* env = std::getenv("BBL_SLICER_CERT_ID"); env && *env)
        return trim(std::string(env));

    const std::string cdir = default_config_dir();
    if (!cdir.empty()) {
#if defined(_WIN32)
        std::string path = cdir + "\\slicer_cert_id.txt";
#else
        std::string path = cdir + "/slicer_cert_id.txt";
#endif
        std::string text = trim(slurp_file(path));
        if (!text.empty()) return text;
    }

    return {};
}

// ---------------------------------------------------------------------------
// Key loading — EVP_PKEY_* only; no RSA_new / RSA_free
// ---------------------------------------------------------------------------

// Parse an RSA private key from PEM text (PKCS#1 or PKCS#8).
// Returns nullptr on failure (call openssl_last_error_string() afterwards).
EvpPkeyPtr load_evp_pkey_from_pem(const std::string& pem)
{
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) return nullptr;
    // PEM_read_bio_PrivateKey handles both "RSA PRIVATE KEY" (PKCS#1)
    // and "PRIVATE KEY" (PKCS#8) headers and returns an EVP_PKEY*
    // directly — no RSA* intermediate needed.
    EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr,
                                             nullptr, nullptr);
    return EvpPkeyPtr{raw};
}

// ---------------------------------------------------------------------------
// Base64 encoder (portable, no OpenSSL BIO dependency)
// ---------------------------------------------------------------------------

std::string base64_encode(const unsigned char* data, std::size_t len)
{
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 2 < len) {
        unsigned w = (static_cast<unsigned>(data[i    ]) << 16)
                   | (static_cast<unsigned>(data[i + 1]) << 8)
                   |  static_cast<unsigned>(data[i + 2]);
        out += kTable[(w >> 18) & 0x3f];
        out += kTable[(w >> 12) & 0x3f];
        out += kTable[(w >>  6) & 0x3f];
        out += kTable[ w        & 0x3f];
        i += 3;
    }
    if (i + 1 == len) {
        unsigned w = static_cast<unsigned>(data[i]) << 16;
        out += kTable[(w >> 18) & 0x3f];
        out += kTable[(w >> 12) & 0x3f];
        out += '=';
        out += '=';
    } else if (i + 2 == len) {
        unsigned w = (static_cast<unsigned>(data[i    ]) << 16)
                   | (static_cast<unsigned>(data[i + 1]) << 8);
        out += kTable[(w >> 18) & 0x3f];
        out += kTable[(w >> 12) & 0x3f];
        out += kTable[(w >>  6) & 0x3f];
        out += '=';
    }
    return out;
}

// ---------------------------------------------------------------------------
// Canonical JSON for the payload to be signed
// ---------------------------------------------------------------------------

// Given the raw `print_json` string ({"print":{...}}), extract and
// re-serialize the inner "print" object with sorted keys (std::map
// guarantees lexicographic order), then wrap back to {"print":{...}}.
// Returns an empty string on parse failure.
std::string canonical_print_json(const std::string& print_json)
{
    std::string err;
    auto root = obn::json::parse(print_json, &err);
    if (!root) {
        OBN_WARN("signing: failed to parse print_json: %s", err.c_str());
        return {};
    }
    const auto& print_val = root->find("print");
    if (print_val.is_null()) {
        OBN_WARN("signing: print_json has no 'print' key");
        return {};
    }
    // dump() re-emits the object with std::map's sorted key order —
    // that IS the canonical order the stock plugin signs.
    std::string inner = print_val.dump();
    return std::string("{\"print\":") + inner + "}";
}

// ---------------------------------------------------------------------------
// JSON envelope builder (manual, to control field order precisely)
// ---------------------------------------------------------------------------

// Minimal JSON string escape (only control chars and double-quote).
static std::string json_str(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (unsigned char c : s) {
        if (c == '"')       { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c < 0x20)  { char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", c); out += buf; }
        else                { out += static_cast<char>(c); }
    }
    out += '"';
    return out;
}

std::string build_envelope_json(const std::string&  cert_id,
                                std::size_t          payload_len,
                                const std::string&   sign_b64,
                                const obn::json::Value& print_val)
{
    // Emit header fields in the same order as the stock plugin capture.
    std::string out;
    out += "{\"header\":{";
    out += "\"cert_id\":";    out += json_str(cert_id);
    out += ",\"payload_len\":"; out += std::to_string(payload_len);
    out += ",\"sign_alg\":\"RSA_SHA256\"";
    out += ",\"sign_string\":"; out += json_str(sign_b64);
    out += ",\"sign_ver\":\"v1.0\"";
    out += "},\"print\":";
    out += print_val.dump();
    out += "}";
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

SignResult sign_print_command(const std::string& print_json, const Config& cfg)
{
    SignResult result;

    // --- 1. Resolve canonical payload to sign ---
    const std::string to_sign = canonical_print_json(print_json);
    if (to_sign.empty()) {
        result.error = "signing: could not extract canonical print payload";
        return result;
    }
    const std::size_t payload_len = to_sign.size();

    // --- 2. Resolve private key ---
    const std::string key_pem = resolve_key_pem(cfg);
    if (key_pem.empty()) {
        result.error =
            "signing: no RSA private key available "
            "(set BBL_SLICER_KEY or place slicer_key.pem in the BambuStudio "
            "config directory)";
        return result;
    }

    // --- 3. Load EVP_PKEY — no RSA_new / EVP_PKEY_assign_RSA ---
    EvpPkeyPtr pkey = load_evp_pkey_from_pem(key_pem);
    if (!pkey) {
        result.error = "signing: PEM_read_bio_PrivateKey failed: "
                     + openssl_last_error_string();
        return result;
    }

    // --- 4. Sign: EVP_DigestSignInit + EVP_PKEY_CTX_set_rsa_padding ---
    EvpMdCtxPtr mdctx{EVP_MD_CTX_new()};
    if (!mdctx) {
        result.error = "signing: EVP_MD_CTX_new failed: "
                     + openssl_last_error_string();
        return result;
    }

    EVP_PKEY_CTX* pctx = nullptr;   // borrowed — owned by mdctx
    if (EVP_DigestSignInit(mdctx.get(), &pctx,
                           EVP_sha256(), nullptr, pkey.get()) <= 0) {
        result.error = "signing: EVP_DigestSignInit failed: "
                     + openssl_last_error_string();
        return result;
    }
    // PKCS#1 v1.5 padding — the same mode the stock plugin uses.
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        result.error = "signing: EVP_PKEY_CTX_set_rsa_padding failed: "
                     + openssl_last_error_string();
        return result;
    }

    // Two-shot: first call with nullptr output to obtain the sig length.
    const auto* msg    = reinterpret_cast<const unsigned char*>(to_sign.data());
    const auto  msg_sz = to_sign.size();
    std::size_t siglen = 0;
    if (EVP_DigestSign(mdctx.get(), nullptr, &siglen, msg, msg_sz) <= 0) {
        result.error = "signing: EVP_DigestSign(size query) failed: "
                     + openssl_last_error_string();
        return result;
    }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx.get(), sig.data(), &siglen, msg, msg_sz) <= 0) {
        result.error = "signing: EVP_DigestSign failed: "
                     + openssl_last_error_string();
        return result;
    }
    sig.resize(siglen);

    // --- 5. Base64 encode ---
    const std::string sig_b64 = base64_encode(sig.data(), sig.size());

    // --- 6. Resolve cert_id ---
    const std::string cert_id = resolve_cert_id(cfg);
    if (cert_id.empty()) {
        OBN_WARN("signing: no cert_id found — envelope will have an empty "
                 "cert_id; non-Developer-Mode firmware will reject it");
    }

    // --- 7. Build envelope ---
    // Re-parse to get the sorted print Value for dump().
    std::string perr;
    auto root = obn::json::parse(print_json, &perr);
    const auto& print_val = root->find("print");

    result.envelope_json = build_envelope_json(cert_id, payload_len,
                                               sig_b64, print_val);
    result.ok = true;
    return result;
}

} // namespace obn::signing
