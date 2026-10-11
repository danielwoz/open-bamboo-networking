// Tests for src/studio_session.cpp — decrypting Bambu Studio's
// BambuNetworkEngine.conf and mapping it onto an obn::auth::Session. Builds its
// own encrypted conf with a known key; no real credentials required.

#include "obn/studio_session.hpp"

#include <openssl/evp.h>

#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <stdlib.h>   // mkdtemp, setenv (POSIX; macOS needs the C headers)
#include <unistd.h>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                 \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

namespace fs = std::filesystem;

static const char kKey[16] = {'0','1','2','3','4','5','6','7',
                              '8','9','a','b','c','d','e','f'};

// AES-128-ECB, no padding; pads the plaintext up to a block boundary with NULs
// (matching how Bambu Studio stores the conf — the importer strips them).
static std::vector<uint8_t> encrypt_conf(const std::string& plain, const unsigned char* key)
{
    std::vector<uint8_t> in(plain.begin(), plain.end());
    while (in.size() % 16 != 0) in.push_back('\0');
    std::vector<uint8_t> out(in.size() + 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int n = 0, f = 0;
    EVP_EncryptUpdate(ctx, out.data(), &n, in.data(), (int)in.size());
    EVP_EncryptFinal_ex(ctx, out.data() + n, &f);
    EVP_CIPHER_CTX_free(ctx);
    out.resize(n + f);
    return out;
}

static void write_file(const fs::path& p, const std::vector<uint8_t>& bytes)
{
    std::ofstream o(p, std::ios::binary);
    o.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
}
static void write_file(const fs::path& p, const std::string& s)
{
    write_file(p, std::vector<uint8_t>(s.begin(), s.end()));
}

static const char* kConfJson =
    "{\"last_monitor_machine\":\"00M00A000000000\","
    "\"user\":{\"account\":\"tester@example.com\",\"token\":\"tok-abc\","
    "\"refresh_token\":\"ref-xyz\",\"user_id\":\"424242\",\"name\":\"Test User\","
    "\"avatar\":\"https://example.com/a.png\",\"expires_in\":1900000000,"
    "\"login_status\":0}}";

static int test_import_raw_key(const fs::path& base)
{
    fs::path dir = base / "raw";
    fs::create_directories(dir);
    write_file(dir / "network_engine.key",
               std::vector<uint8_t>(kKey, kKey + 16));
    write_file(dir / "BambuNetworkEngine.conf",
               encrypt_conf(kConfJson, (const unsigned char*)kKey));

    auto s = obn::studio_session::import_from_studio_conf(dir.string());
    CHECK(s.has_value());
    CHECK(s->logged_in());
    CHECK(s->account == "tester@example.com");
    CHECK(s->access_token == "tok-abc");
    CHECK(s->refresh_token == "ref-xyz");
    CHECK(s->user_id == "424242");
    CHECK(s->user_name == "Test User");
    CHECK(s->avatar == "https://example.com/a.png");
    long long exp = std::chrono::duration_cast<std::chrono::seconds>(
                        s->expires_at.time_since_epoch()).count();
    CHECK(exp == 1900000000);
    return 0;
}

static int test_import_hex_key(const fs::path& base)
{
    fs::path dir = base / "hex";
    fs::create_directories(dir);
    // 32 hex chars encoding the same 16 key bytes.
    std::string hex;
    for (unsigned char c : std::string(kKey, kKey + 16)) {
        char b[3];
        std::snprintf(b, sizeof(b), "%02x", c);
        hex += b;
    }
    write_file(dir / "network_engine.key", hex);
    write_file(dir / "BambuNetworkEngine.conf",
               encrypt_conf(kConfJson, (const unsigned char*)kKey));

    auto s = obn::studio_session::import_from_studio_conf(dir.string());
    CHECK(s.has_value());
    CHECK(s->user_id == "424242");
    return 0;
}

static int test_missing_conf(const fs::path& base)
{
    fs::path dir = base / "empty";
    fs::create_directories(dir);
    auto s = obn::studio_session::import_from_studio_conf(dir.string());
    CHECK(!s.has_value());
    return 0;
}

static int test_wrong_key(const fs::path& base)
{
    fs::path dir = base / "wrongkey";
    fs::create_directories(dir);
    unsigned char other[16];
    for (int i = 0; i < 16; ++i) other[i] = (unsigned char)(0xA0 + i);
    write_file(dir / "network_engine.key",
               std::vector<uint8_t>(other, other + 16));
    write_file(dir / "BambuNetworkEngine.conf",
               encrypt_conf(kConfJson, (const unsigned char*)kKey));
    // Decrypts to garbage -> not JSON -> no session.
    auto s = obn::studio_session::import_from_studio_conf(dir.string());
    CHECK(!s.has_value());
    return 0;
}

int main()
{
    // Isolate default_studio_config_dir() into the sandbox so no real
    // ~/.config/BambuStudio leaks into the "missing conf" case.
    char tmpl[] = "/tmp/obn_studio_test_XXXXXX";
    char* d = mkdtemp(tmpl);
    if (!d) { std::cerr << "mkdtemp failed\n"; return 1; }
    fs::path base = d;
    setenv("HOME", base.c_str(), 1);
    setenv("XDG_CONFIG_HOME", (base / "xdg").c_str(), 1);

    int rc = 0;
    rc |= test_import_raw_key(base);
    rc |= test_import_hex_key(base);
    rc |= test_missing_conf(base);
    rc |= test_wrong_key(base);

    std::error_code ec;
    fs::remove_all(base, ec);

    if (rc == 0) std::cout << "studio_session_test: ok\n";
    return rc;
}
