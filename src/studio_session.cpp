#include "obn/studio_session.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

// Build-time-embedded AES key fallback (empty unless OBN_AES_KEY was set at
// configure time). See cmake/obn_embedded_signing.h.in.
#include "obn_embedded_signing.h"

#include <openssl/evp.h>

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace obn::studio_session {

namespace {

namespace fs = std::filesystem;

// Platform default Bambu Studio config directory, where the stock plugin keeps
// network_engine.key and BambuNetworkEngine.conf. Empty when it cannot be
// determined (no HOME/APPDATA in the environment).
static std::string default_studio_config_dir()
{
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata && *appdata)
        return (fs::path(appdata) / "BambuStudio").string();
    return {};
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home && *home)
        return (fs::path(home) / "Library" / "Application Support" / "BambuStudio").string();
    return {};
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
        return (fs::path(xdg) / "BambuStudio").string();
    if (const char* home = std::getenv("HOME"); home && *home)
        return (fs::path(home) / ".config" / "BambuStudio").string();
    return {};
#endif
}

// Reads a whole file into bytes. Empty on any failure.
static std::vector<uint8_t> read_file_bytes(const fs::path& path)
{
    std::error_code ec;
    if (!fs::exists(path, ec)) return {};
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(ifs),
                                std::istreambuf_iterator<char>());
}

// Interprets raw key material as a 16-byte AES-128 key: 16 bytes verbatim, or
// 32 hex characters (optionally whitespace-padded). Empty vector otherwise.
static std::vector<uint8_t> parse_aes128_key(std::string raw)
{
    if (raw.size() == 16)
        return std::vector<uint8_t>(raw.begin(), raw.end());

    const auto ws = [](char c) { return c == '\r' || c == '\n' || c == ' ' || c == '\t'; };
    while (!raw.empty() && ws(raw.back())) raw.pop_back();
    std::size_t start = 0;
    while (start < raw.size() && ws(raw[start])) ++start;
    raw = raw.substr(start);

    if (raw.size() == 16)
        return std::vector<uint8_t>(raw.begin(), raw.end());

    if (raw.size() == 32) {
        std::vector<uint8_t> bytes;
        bytes.reserve(16);
        for (std::size_t i = 0; i < 32; i += 2) {
            const char h1 = raw[i], h2 = raw[i + 1];
            if (!std::isxdigit(static_cast<unsigned char>(h1)) ||
                !std::isxdigit(static_cast<unsigned char>(h2)))
                return {};
            bytes.push_back(static_cast<uint8_t>(std::stoi(raw.substr(i, 2), nullptr, 16)));
        }
        return bytes;
    }
    return {};
}

// network_engine.key from config_dir, then the Studio default dir, then the
// build-time-embedded key. Empty vector when none yields a 16-byte key.
static std::vector<uint8_t> resolve_key(const std::string& config_dir,
                                        const std::string& studio_dir)
{
    for (const std::string& dir : {config_dir, studio_dir}) {
        if (dir.empty()) continue;
        auto raw = read_file_bytes(fs::path(dir) / "network_engine.key");
        if (raw.empty()) continue;
        auto key = parse_aes128_key(std::string(raw.begin(), raw.end()));
        if (key.size() == 16) return key;
    }
    if (obn::signing::embedded::kAesKey[0] != '\0') {
        auto key = parse_aes128_key(obn::signing::embedded::kAesKey);
        if (key.size() == 16) return key;
    }
    return {};
}

// AES-128-ECB, no padding. Empty on failure.
static std::string aes128_ecb_decrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& ct)
{
    if (key.size() != 16 || ct.empty() || ct.size() % 16 != 0) return {};
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) return {};
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1)
        return {};
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    std::vector<uint8_t> out(ct.size());
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &out_len, ct.data(),
                          static_cast<int>(ct.size())) != 1)
        return {};
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + out_len, &final_len) != 1)
        return {};
    out.resize(static_cast<std::size_t>(out_len + final_len));
    std::string s(out.begin(), out.end());
    while (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

} // namespace

std::optional<obn::auth::Session> import_from_studio_conf(const std::string& config_dir)
{
    const std::string studio_dir = default_studio_config_dir();

    fs::path conf_path;
    for (const std::string& dir : {config_dir, studio_dir}) {
        if (dir.empty()) continue;
        fs::path p = fs::path(dir) / "BambuNetworkEngine.conf";
        std::error_code ec;
        if (fs::exists(p, ec)) { conf_path = p; break; }
    }
    if (conf_path.empty()) return std::nullopt;

    const std::vector<uint8_t> key = resolve_key(config_dir, studio_dir);
    if (key.size() != 16) {
        OBN_WARN("studio import: %s present but no usable network_engine.key",
                 conf_path.string().c_str());
        return std::nullopt;
    }

    const std::vector<uint8_t> ct = read_file_bytes(conf_path);
    const std::string json_str = aes128_ecb_decrypt(key, ct);
    if (json_str.empty()) {
        OBN_WARN("studio import: could not decrypt %s", conf_path.string().c_str());
        return std::nullopt;
    }

    std::string err;
    auto root = obn::json::parse(json_str, &err);
    if (!root) {
        OBN_WARN("studio import: %s decrypted but not JSON (%s)",
                 conf_path.string().c_str(), err.c_str());
        return std::nullopt;
    }

    obn::auth::Session s;
    s.account       = root->find("user.account").as_string();
    s.access_token  = root->find("user.token").as_string();
    s.refresh_token = root->find("user.refresh_token").as_string();
    s.user_id       = root->find("user.user_id").as_string();
    s.user_name     = root->find("user.name").as_string();
    s.nick_name     = root->find("user.name").as_string();
    s.avatar        = root->find("user.avatar").as_string();

    // Bambu Studio stores expires_in / refresh_expires_in as absolute Unix
    // epoch seconds, not a relative lifetime.
    const std::int64_t exp = root->find("user.expires_in").as_int(0);
    if (exp > 0)
        s.expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(exp));

    if (!s.logged_in()) {
        OBN_WARN("studio import: %s has no usable token", conf_path.string().c_str());
        return std::nullopt;
    }

    OBN_INFO("studio import: loaded cloud session from %s (user_id=%s)",
             conf_path.string().c_str(), s.user_id.c_str());
    return s;
}

} // namespace obn::studio_session
