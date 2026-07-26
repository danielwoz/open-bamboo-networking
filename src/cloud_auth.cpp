#include "obn/cloud_auth.hpp"
#include "obn/identity_headers.hpp"

#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <sstream>

namespace obn::cloud {

namespace {

std::string refresh_body(const std::string& refresh)
{
    std::ostringstream os;
    os << '{'
       << "\"refreshToken\":" << obn::json::escape(refresh)
       << '}';
    return os.str();
}

// Extract the common "accessToken" shape. Fields that are absent stay
// empty; callers check `ok` first.
void fill_auth_fields(const obn::json::Value& root, AuthResult& r)
{
    r.access_token  = root.find("accessToken").as_string();
    r.refresh_token = root.find("refreshToken").as_string();
    r.expires_in    = root.find("expiresIn").as_int(0);
    r.refresh_expires_in = root.find("refreshExpiresIn").as_int(0);
    r.login_type    = root.find("loginType").as_string();
    // tfaKey is sometimes called "tfa_key"; check both.
    auto tfa1 = root.find("tfaKey").as_string();
    auto tfa2 = root.find("tfa_key").as_string();
    r.tfa_key = !tfa1.empty() ? tfa1 : tfa2;
}

std::string api_error(const obn::json::Value& root, long status)
{
    auto msg = root.find("message").as_string();
    if (msg.empty()) msg = root.find("error").as_string();
    if (msg.empty()) msg = "http " + std::to_string(status);
    return msg;
}

} // namespace

std::string api_host(const std::string& region)
{
    return obn::config::cloud_api_host_for(obn::config::current(), region);
}

std::string web_host(const std::string& region)
{
    return obn::config::cloud_web_host_for(obn::config::current(), region);
}

AuthResult login_with_ticket(const std::string& region,
                             const std::string& ticket)
{
    AuthResult r;
    if (ticket.empty()) {
        r.error_message = "empty ticket";
        return r;
    }
    // Endpoint confirmed from the original plugin's traffic:
    //   POST https://api.bambulab.com/v1/user-service/user/ticket/<TICKET>
    //   body: {"ticket":"<TICKET>"}
    // Response on success (HTTP 200):
    //   {"accessToken":"...","refreshToken":"...","expiresIn":31536000,
    //    "refreshExpiresIn":...,"tfaKey":"","accessMethod":"ticket",
    //    "loginType":"","firstAppLogin":false}
    // The ticket is single-use and short-lived; any failure here means
    // Studio will re-open the login dialog.
    std::string url  = api_host(region) + "/v1/user-service/user/ticket/" + ticket;
    std::string body = std::string("{\"ticket\":") + obn::json::escape(ticket) + "}";
    // Pre-auth: send the stock identity block (correct User-Agent, X-BBL-* set)
    // but no Authorization/X-BBL-Client-ID (we have no token or user id yet).
    auto resp = obn::http::post_json(url, body,
        obn::bbl::identity_headers(/*token*/std::string{}, /*uid*/std::string{},
                                   /*include_client_id*/false, /*with_content_type*/true));
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

AuthResult refresh_token(const std::string& region,
                         const std::string& refresh)
{
    AuthResult r;
    // Note: the endpoint name varies between Studio versions and the HA
    // community docs (`/v1/user-service/user/refreshtoken` or
    // `/v1/user-service/user/refresh-token`). We try the more common
    // dash-less form; if it 404s we'll iterate later.
    // Pre-auth refresh: stock identity block, no Authorization/X-BBL-Client-ID.
    auto resp = obn::http::post_json(api_host(region) + "/v1/user-service/user/refreshtoken",
                                     refresh_body(refresh),
        obn::bbl::identity_headers(/*token*/std::string{}, /*uid*/std::string{},
                                   /*include_client_id*/false, /*with_content_type*/true));
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

ProfileResult get_profile(const std::string& region,
                          const std::string& access_token)
{
    ProfileResult r;
    // Full stock identity block (ordered by http::perform). No X-BBL-Client-ID:
    // this runs before we know the user id (it is what fetches it).
    auto hdrs = obn::bbl::identity_headers(access_token, /*user_id*/std::string{},
                                           /*include_client_id*/false,
                                           /*with_content_type*/true);
    auto resp = obn::http::get_json(api_host(region) + "/v1/user-service/my/profile", hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    if (resp.status_code != 200) {
        r.error_message = "http " + std::to_string(resp.status_code);
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) { r.error_message = "bad JSON: " + perr; return r; }
    // The profile response looks like:
    //   {"uidStr":"...","name":"...","avatar":"...","account":"...","nickname":"..."}
    // (field names vary slightly across account regions; we accept a few
    // common spellings).
    r.user_id   = root->find("uidStr").as_string();
    if (r.user_id.empty()) {
        auto uid = root->find("uid").as_int(0);
        if (uid != 0) r.user_id = std::to_string(uid);
    }
    r.user_name = root->find("name").as_string();
    r.nick_name = root->find("nickname").as_string();
    if (r.nick_name.empty()) r.nick_name = root->find("nickName").as_string();
    r.avatar    = root->find("avatar").as_string();
    r.account   = root->find("account").as_string();
    // setting.isFirmwareBetaOpen controls whether the cloud firmware
    // endpoint returns beta firmware entries for this user's devices.
    r.firmware_beta_open = root->find("setting.isFirmwareBetaOpen").as_bool();
    r.ok = true;
    return r;
}

std::string decrypt_device_key(const std::string& base64_key, const std::string& aes256_key)
{
    if (base64_key.empty() || aes256_key.empty()) return {};

    // 1. Decode base64 encrypted payload
    std::vector<uint8_t> cipher(base64_key.size());
    EVP_ENCODE_CTX* b64_ctx = EVP_ENCODE_CTX_new();
    if (!b64_ctx) return {};
    EVP_DecodeInit(b64_ctx);
    int out_len = 0, final_len = 0;
    EVP_DecodeUpdate(b64_ctx, cipher.data(), &out_len,
                     reinterpret_cast<const unsigned char*>(base64_key.data()),
                     static_cast<int>(base64_key.size()));
    EVP_DecodeFinal(b64_ctx, cipher.data() + out_len, &final_len);
    EVP_ENCODE_CTX_free(b64_ctx);
    cipher.resize(out_len + final_len);

    if (cipher.size() < 16) return {};

    // 2. Prepare 32-byte AES key
    std::vector<uint8_t> raw_key;
    if (aes256_key.size() == 32) {
        raw_key.assign(aes256_key.begin(), aes256_key.end());
    } else {
        raw_key.resize(aes256_key.size());
        EVP_ENCODE_CTX* k_ctx = EVP_ENCODE_CTX_new();
        if (k_ctx) {
            EVP_DecodeInit(k_ctx);
            int k_out = 0, k_fin = 0;
            EVP_DecodeUpdate(k_ctx, raw_key.data(), &k_out,
                             reinterpret_cast<const unsigned char*>(aes256_key.data()),
                             static_cast<int>(aes256_key.size()));
            EVP_DecodeFinal(k_ctx, raw_key.data() + k_out, &k_fin);
            EVP_ENCODE_CTX_free(k_ctx);
            raw_key.resize(k_out + k_fin);
        }
    }
    if (raw_key.size() != 32) {
        OBN_INFO("decrypt_device_key: key size %zu != 32 bytes", raw_key.size());
        return {};
    }

    // 3. AES-256-CBC Decrypt
    std::vector<uint8_t> plain(cipher.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    unsigned char iv[16] = {0};
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, raw_key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int p_out1 = 0, p_out2 = 0;
    if (EVP_DecryptUpdate(ctx, plain.data(), &p_out1, cipher.data(), static_cast<int>(cipher.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (EVP_DecryptFinal_ex(ctx, plain.data() + p_out1, &p_out2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    plain.resize(p_out1 + p_out2);
    return std::string(plain.begin(), plain.end());
}

DeviceCertResult fetch_device_cert(const std::string& region,
                                   const std::string& access_token,
                                   const std::string& application_token,
                                   const std::string& aes256_key)
{
    DeviceCertResult r;
    if (application_token.empty()) {
        r.error_message = "application_token required (see cloud_auth.hpp comment)";
        return r;
    }
    // Endpoint confirmed from MITM capture of the stock plugin:
    //   GET /v1/iot-service/api/user/applications/{token}/cert?aes256={key}&ver=1
    const std::string encoded_token = obn::http::url_encode(application_token);
    const std::string encoded_key   = obn::http::url_encode(aes256_key);
    std::string url = api_host(region)
        + "/v1/iot-service/api/user/applications/"
        + encoded_token
        + "/cert?aes256="
        + encoded_key
        + "&ver=1";
    auto hdrs = obn::bbl::identity_headers(access_token, /*user_id*/std::string{},
                                           /*include_client_id*/false,
                                           /*with_content_type*/false);
    auto resp = obn::http::get_json(url, hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    if (resp.status_code != 200) {
        r.error_message = "http " + std::to_string(resp.status_code);
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    r.cert = root->find("cert").as_string();
    {
        auto crl_v = root->find("crl");
        const auto& crl_arr = crl_v.as_array();
        if (!crl_arr.empty()) r.crl = crl_arr[0].as_string();
    }
    std::string enc_key = root->find("key").as_string();
    if (!enc_key.empty() && !aes256_key.empty()) {
        r.key = decrypt_device_key(enc_key, aes256_key);
    } else {
        r.key = enc_key;
    }
    r.ok = !r.cert.empty();
    if (!r.ok) r.error_message = "cert field missing in response";
    return r;
}

} // namespace obn::cloud
