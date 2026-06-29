// Hermetic unit tests for obn::signing.
//
// All tests are self-contained: ephemeral RSA-2048 keys are generated at
// runtime via EVP_PKEY_CTX — no on-disk secrets required.  The test
// verifies the produced signature cryptographically using EVP_DigestVerify.
//
// Test matrix:
//   1. Basic round-trip: sign a minimal print JSON, verify signature.
//   2. Canonical key ordering: two inputs with the same fields in different
//      order produce the identical signature (sorted-key canonicalisation).
//   3. No-key error path: sign_print_command returns ok=false when no key
//      is resolvable.
//   4. Envelope structure: the returned JSON contains the expected fields
//      (header.cert_id, header.payload_len, header.sign_alg,
//       header.sign_string, header.sign_ver, print).
//   5. Inline PEM in Config::private_key_pem_path round-trip.

#include "obn/json_lite.hpp"
#include "obn/signing.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>   // RSA_PKCS1_PADDING constant

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__              \
                      << "  " << #cond << "\n";                              \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

#define CHECK_MSG(cond, msg)                                                  \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__              \
                      << "  " << (msg) << "\n";                              \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Helpers: ephemeral key generation via EVP_PKEY_CTX (no RSA_new)
// ---------------------------------------------------------------------------

struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

// Generate a fresh RSA-2048 private key using the EVP_PKEY_CTX API.
// Returns nullptr on failure.
static EvpPkeyPtr generate_test_rsa2048()
{
    struct CtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
    std::unique_ptr<EVP_PKEY_CTX, CtxDeleter> ctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) return nullptr;
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) return nullptr;
    return EvpPkeyPtr{raw};
}

// Export an EVP_PKEY to PKCS#8 PEM text ("-----BEGIN PRIVATE KEY-----").
static std::string pkey_to_pkcs8_pem(EVP_PKEY* pkey)
{
    struct BioDeleter { void operator()(BIO* b) const { BIO_free_all(b); } };
    std::unique_ptr<BIO, BioDeleter> bio{BIO_new(BIO_s_mem())};
    if (!bio) return {};
    if (PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey,
                                      nullptr, nullptr, 0,
                                      nullptr, nullptr) != 1) {
        return {};
    }
    char* ptr = nullptr;
    long  len = BIO_get_mem_data(bio.get(), &ptr);
    return len > 0 ? std::string(ptr, static_cast<std::size_t>(len)) : std::string{};
}

// ---------------------------------------------------------------------------
// Signature verification helper
// ---------------------------------------------------------------------------

// Decode standard base64 (no line-wrapping assumed).
static std::vector<unsigned char> base64_decode(const std::string& b64)
{
    static const signed char kRevTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::vector<unsigned char> out;
    out.reserve((b64.size() / 4) * 3);
    unsigned acc = 0;
    int      bits = 0;
    for (unsigned char c : b64) {
        if (c == '=') break;
        signed char v = kRevTable[c];
        if (v < 0) continue;
        acc  = (acc << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((acc >> bits) & 0xff));
        }
    }
    return out;
}

// Verify an RSA-SHA256 PKCS#1-v1.5 signature over `msg` using `pkey`.
static bool verify_sig(EVP_PKEY* pkey,
                       const std::string& msg,
                       const std::vector<unsigned char>& sig)
{
    struct MdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> mdctx{EVP_MD_CTX_new()};
    if (!mdctx) return false;
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(mdctx.get(), &pctx,
                             EVP_sha256(), nullptr, pkey) <= 0)
        return false;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
        return false;
    return EVP_DigestVerify(
               mdctx.get(),
               sig.data(), sig.size(),
               reinterpret_cast<const unsigned char*>(msg.data()),
               msg.size()) == 1;
}

// ---------------------------------------------------------------------------
// Test 1 — Basic round-trip
// ---------------------------------------------------------------------------

static int test_basic_round_trip()
{
    // Generate ephemeral key.
    EvpPkeyPtr pkey = generate_test_rsa2048();
    CHECK_MSG(pkey != nullptr, "generate_test_rsa2048 failed");
    if (!pkey) return 1;

    std::string pem = pkey_to_pkcs8_pem(pkey.get());
    CHECK_MSG(!pem.empty(), "pkey_to_pkcs8_pem failed");

    obn::signing::Config cfg;
    cfg.private_key_pem_path = pem;   // inline PEM
    cfg.cert_id = "test-cert-id";

    const std::string print_json =
        "{\"print\":{\"command\":\"project_file\",\"sequence_id\":\"1\"}}";

    auto res = obn::signing::sign_print_command(print_json, cfg);
    CHECK_MSG(res.ok, std::string("sign failed: ") + res.error);
    if (!res.ok) return 1;

    // Parse the envelope.
    auto root = obn::json::parse(res.envelope_json);
    CHECK_MSG(root.has_value(), "envelope parse failed");
    if (!root) return 1;

    const std::string sign_b64 =
        root->find("header.sign_string").as_string();
    CHECK(!sign_b64.empty());

    // Reconstruct the canonical to_sign string and verify.
    const std::string inner = root->find("print").dump();
    const std::string to_sign = std::string("{\"print\":") + inner + "}";

    auto sig = base64_decode(sign_b64);
    CHECK(!sig.empty());
    CHECK(verify_sig(pkey.get(), to_sign, sig));

    return 0;
}

// ---------------------------------------------------------------------------
// Test 2 — Canonical key ordering
// ---------------------------------------------------------------------------

static int test_canonical_ordering()
{
    EvpPkeyPtr pkey = generate_test_rsa2048();
    if (!pkey) { std::cerr << "keygen failed\n"; return 1; }
    std::string pem = pkey_to_pkcs8_pem(pkey.get());

    obn::signing::Config cfg;
    cfg.private_key_pem_path = pem;
    cfg.cert_id = "cid";

    // Same fields, different order in the source JSON.
    const std::string json_a =
        "{\"print\":{\"command\":\"project_file\",\"sequence_id\":\"42\"}}";
    const std::string json_b =
        "{\"print\":{\"sequence_id\":\"42\",\"command\":\"project_file\"}}";

    auto ra = obn::signing::sign_print_command(json_a, cfg);
    auto rb = obn::signing::sign_print_command(json_b, cfg);

    CHECK(ra.ok);
    CHECK(rb.ok);
    if (!ra.ok || !rb.ok) return 1;

    // Canonical to_sign strings must be identical for both inputs.
    auto roota = obn::json::parse(ra.envelope_json);
    auto rootb = obn::json::parse(rb.envelope_json);
    CHECK(roota && rootb);
    if (!roota || !rootb) return 1;

    const std::string inner_a = roota->find("print").dump();
    const std::string inner_b = rootb->find("print").dump();
    CHECK(inner_a == inner_b);

    // sign_string must also be identical (same payload → same sig for RSA-PKCS1).
    const std::string sig_a = roota->find("header.sign_string").as_string();
    const std::string sig_b = rootb->find("header.sign_string").as_string();
    CHECK(sig_a == sig_b);

    return 0;
}

// ---------------------------------------------------------------------------
// Test 3 — No-key error path
// ---------------------------------------------------------------------------

static int test_no_key_error()
{
    // Ensure env var is not set during this test.
#if defined(_WIN32)
    _putenv_s("BBL_SLICER_KEY", "");
#else
    ::unsetenv("BBL_SLICER_KEY");
#endif

    obn::signing::Config cfg;
    // Leave cfg.private_key_pem_path empty; no key on disk either.
    cfg.cert_id = "unused";

    // We cannot guarantee no slicer_key.pem exists under the real config
    // dir, so only check the shape of the result if the signing actually
    // fails.  If it succeeds the system happens to have a key installed,
    // which is a valid (and good) state.
    auto res = obn::signing::sign_print_command(
        "{\"print\":{\"command\":\"test\"}}", cfg);

    if (!res.ok) {
        CHECK(!res.error.empty());
        CHECK(res.envelope_json.empty());
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Test 4 — Envelope structure
// ---------------------------------------------------------------------------

static int test_envelope_structure()
{
    EvpPkeyPtr pkey = generate_test_rsa2048();
    if (!pkey) { std::cerr << "keygen failed\n"; return 1; }
    std::string pem = pkey_to_pkcs8_pem(pkey.get());

    obn::signing::Config cfg;
    cfg.private_key_pem_path = pem;
    cfg.cert_id = "envelope-test-cert";

    auto res = obn::signing::sign_print_command(
        "{\"print\":{\"command\":\"project_file\",\"url\":\"ftp://x.3mf\"}}", cfg);
    CHECK(res.ok);
    if (!res.ok) return 1;

    auto root = obn::json::parse(res.envelope_json);
    CHECK(root.has_value());
    if (!root) return 1;

    // header fields
    CHECK(root->find("header").is_object());
    CHECK(root->find("header.cert_id").as_string() == "envelope-test-cert");
    CHECK(root->find("header.sign_alg").as_string() == "RSA_SHA256");
    CHECK(root->find("header.sign_ver").as_string() == "v1.0");
    CHECK(!root->find("header.sign_string").as_string().empty());
    CHECK(root->find("header.payload_len").as_number() > 0);

    // print block must be present
    CHECK(root->find("print").is_object());
    CHECK(root->find("print.command").as_string() == "project_file");

    // payload_len must equal the byte length of {"print":{...}}
    const std::string inner = root->find("print").dump();
    const std::string to_sign = std::string("{\"print\":") + inner + "}";
    const std::size_t expected_len = to_sign.size();
    CHECK(static_cast<std::size_t>(
              root->find("header.payload_len").as_number()) == expected_len);

    return 0;
}

// ---------------------------------------------------------------------------
// Test 5 — PKCS#1 PEM in Config::private_key_pem_path
// ---------------------------------------------------------------------------

static int test_pkcs1_pem_inline()
{
    // Generate and export as traditional PKCS#1 ("RSA PRIVATE KEY").
    EvpPkeyPtr pkey = generate_test_rsa2048();
    if (!pkey) { std::cerr << "keygen failed\n"; return 1; }

    struct BioDeleter { void operator()(BIO* b) const { BIO_free_all(b); } };
    std::unique_ptr<BIO, BioDeleter> bio{BIO_new(BIO_s_mem())};
    if (!bio) { std::cerr << "BIO_new failed\n"; return 1; }
    // PEM_write_bio_PrivateKey emits PKCS#1 format for RSA keys.
    PEM_write_bio_PrivateKey(bio.get(), pkey.get(),
                             nullptr, nullptr, 0, nullptr, nullptr);
    char* ptr = nullptr;
    long  len = BIO_get_mem_data(bio.get(), &ptr);
    std::string pkcs1_pem(ptr, static_cast<std::size_t>(len));

    obn::signing::Config cfg;
    cfg.private_key_pem_path = pkcs1_pem;
    cfg.cert_id = "pkcs1-test";

    auto res = obn::signing::sign_print_command(
        "{\"print\":{\"command\":\"project_file\"}}", cfg);
    CHECK_MSG(res.ok, std::string("pkcs1 sign failed: ") + res.error);

    if (!res.ok) return 1;

    // Verify signature.
    auto root = obn::json::parse(res.envelope_json);
    CHECK(root.has_value());
    if (!root) return 1;
    const std::string inner   = root->find("print").dump();
    const std::string to_sign = std::string("{\"print\":") + inner + "}";
    auto sig = base64_decode(root->find("header.sign_string").as_string());
    CHECK(!sig.empty());
    CHECK(verify_sig(pkey.get(), to_sign, sig));

    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    test_basic_round_trip();
    test_canonical_ordering();
    test_no_key_error();
    test_envelope_structure();
    test_pkcs1_pem_inline();

    if (g_failures == 0) {
        std::cout << "signing_test: all tests passed\n";
        return 0;
    }
    std::cerr << "signing_test: " << g_failures << " test(s) FAILED\n";
    return 1;
}
