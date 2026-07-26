// obn_fetch_device_cert — CLI tool to fetch and decrypt device certificates and private keys
// from Bambu Cloud API in real-time.
//
// Reads credentials from obn.auth.json or encrypted BambuNetworkEngine.conf,
// generates an ephemeral 32-byte AES key, calls fetch_device_cert(), and
// decrypts the private key returned by the live web API.

#include "obn/auth.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/identity_headers.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define LOG(fmt, ...) do { std::fprintf(stdout, "[fetch_cert] " fmt "\n", ##__VA_ARGS__); std::fflush(stdout); } while (0)
#define ERR(fmt, ...) do { std::fprintf(stderr, "[fetch_cert] " fmt "\n", ##__VA_ARGS__); } while (0)

static std::string default_config_dir() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA")) {
        return (std::filesystem::path(appdata) / "BambuStudio").string();
    }
    return ".";
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
        return (std::filesystem::path(xdg) / "BambuStudio").string();
    }
    if (const char* home = std::getenv("HOME")) {
        return (std::filesystem::path(home) / ".config" / "BambuStudio").string();
    }
    return ".";
#endif
}

static std::string generate_uuid_v4() {
    unsigned char buf[16];
    if (RAND_bytes(buf, 16) != 1) return "";
    buf[6] = (buf[6] & 0x0f) | 0x40; // Version 4
    buf[8] = (buf[8] & 0x3f) | 0x80; // Variant 1

    char str[37];
    std::snprintf(str, sizeof(str),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  buf[0], buf[1], buf[2], buf[3],
                  buf[4], buf[5],
                  buf[6], buf[7],
                  buf[8], buf[9],
                  buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
    return std::string(str);
}

static std::string machine_id_to_uuid(const std::string& machine_id) {
    unsigned char md[16];
    EVP_Digest(machine_id.data(), machine_id.size(), md, nullptr, EVP_md5(), nullptr);
    md[6] = (md[6] & 0x0f) | 0x40;
    md[8] = (md[8] & 0x3f) | 0x80;
    char str[37];
    std::snprintf(str, sizeof(str),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  md[0], md[1], md[2], md[3],
                  md[4], md[5],
                  md[6], md[7],
                  md[8], md[9],
                  md[10], md[11], md[12], md[13], md[14], md[15]);
    return std::string(str);
}

static std::vector<uint8_t> load_network_engine_key(const std::string& config_dir) {
    std::filesystem::path key_path = std::filesystem::path(config_dir) / "network_engine.key";
    std::string def_dir = default_config_dir();
    if (!std::filesystem::exists(key_path) && config_dir != def_dir) {
        std::filesystem::path alt_path = std::filesystem::path(def_dir) / "network_engine.key";
        if (std::filesystem::exists(alt_path)) key_path = alt_path;
    }
    if (!std::filesystem::exists(key_path)) return {};

    std::ifstream ifs(key_path, std::ios::binary);
    if (!ifs.is_open()) return {};
    std::string raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    if (raw.size() == 16) {
        return std::vector<uint8_t>(raw.begin(), raw.end());
    }
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' ')) {
        raw.pop_back();
    }
    if (raw.size() == 16) {
        return std::vector<uint8_t>(raw.begin(), raw.end());
    }
    return {};
}

int main(int argc, char** argv) {
    std::string config_dir = default_config_dir();
    std::string access_token, user_id, region = "us", app_token;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config-dir" && i + 1 < argc)   config_dir   = argv[++i];
        else if (a == "--token" && i + 1 < argc)    access_token = argv[++i];
        else if (a == "--user-id" && i + 1 < argc)  user_id      = argv[++i];
        else if (a == "--region" && i + 1 < argc)   region       = argv[++i];
        else if (a == "--app-token" && i + 1 < argc) app_token   = argv[++i];
    }

    obn::config::load_or_create(config_dir);
    obn::http::global_init();

    // 1. Try loading credentials from obn.auth.json
    obn::auth::Store store(obn::config::path_in_dir("obn.auth.json"));
    store.load();
    obn::auth::Session sess = store.snapshot();

    if (!access_token.empty()) sess.access_token = access_token;
    if (!user_id.empty())      sess.user_id      = user_id;
    if (!region.empty())       sess.region       = region;

    // 2. Try loading from BambuNetworkEngine.conf if still empty
    if (sess.access_token.empty()) {
        std::string conf_path = config_dir + "/BambuNetworkEngine.conf";
        if (std::filesystem::exists(conf_path)) {
            LOG("reading credentials from %s", conf_path.c_str());
            std::vector<uint8_t> key = load_network_engine_key(config_dir);
            if (key.size() == 16) {
                std::ifstream ifs(conf_path, std::ios::binary);
                if (ifs.is_open()) {
                    std::vector<uint8_t> conf_data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    ifs.close();

                    std::vector<uint8_t> decrypted(conf_data.size());
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
                    EVP_CIPHER_CTX_set_padding(ctx, 0);
                    int out_len = 0;
                    EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, conf_data.data(), conf_data.size());
                    EVP_CIPHER_CTX_free(ctx);
                    decrypted.resize(out_len);

                    std::string json_str(decrypted.begin(), decrypted.end());
                    while (!json_str.empty() && json_str.back() == '\0') json_str.pop_back();

                    auto root = obn::json::parse(json_str);
                    if (root) {
                        std::string t = root->find("user").find("token").as_string();
                        std::string u = root->find("user").find("user_id").as_string();
                        if (!t.empty()) sess.access_token = t;
                        if (!u.empty()) sess.user_id = u;
                        LOG("loaded cloud token from BambuNetworkEngine.conf (user_id=%s)", sess.user_id.c_str());
                        LOG("decrypted conf JSON:\n%s", json_str.c_str());
                    }
                }
            } else {
                ERR("network_engine.key missing or invalid size != 16 bytes");
            }
        }
    }

    if (app_token.empty()) {
        app_token = generate_uuid_v4();
        LOG("no --app-token specified, generated random UUID v4: %s", app_token.c_str());
    }

    if (sess.access_token.empty() || app_token.empty()) {
        ERR("no valid credentials found. Please log in via Studio/Orca or pass --token and --app-token");
        return 1;
    }

    // 3. Generate random 32-byte AES key
    unsigned char raw_aes_key[32];
    if (RAND_bytes(raw_aes_key, sizeof(raw_aes_key)) != 1) {
        ERR("failed to generate random AES key via OpenSSL RAND_bytes");
        return 1;
    }

    std::string aes256_key(reinterpret_cast<char*>(raw_aes_key), sizeof(raw_aes_key));

    LOG("checking profile with access token...");
    auto prof = obn::cloud::get_profile(sess.region, sess.access_token);
    LOG("get_profile HTTP status: %ld (ok=%d, nick_name=%s, err=%s)",
        prof.http_status, prof.ok, prof.nick_name.c_str(), prof.error_message.c_str());

    LOG("requesting device cert from Bambu Cloud API...");
    LOG("region: %s", sess.region.c_str());
    LOG("application token: %s", app_token.c_str());

    // 4. Call live fetch_device_cert API
    auto res = obn::cloud::fetch_device_cert(sess.region, sess.access_token, app_token, aes256_key);

    LOG("HTTP status: %ld", res.http_status);
    LOG("Raw Response Body:\n%s", res.raw_body.c_str());

    if (!res.ok) {
        ERR("fetch_device_cert failed: %s", res.error_message.c_str());
        return 1;
    }

    LOG("SUCCESS! Received certificate chain and key from Bambu Web API.");
    LOG("Cert chain length: %zu bytes", res.cert.size());
    if (!res.crl.empty()) LOG("CRL length: %zu bytes", res.crl.size());

    if (!res.key.empty()) {
        LOG("Decrypted Private Key:\n%s", res.key.c_str());
    } else {
        ERR("Private key field missing or failed decryption.");
    }

    return 0;
}
