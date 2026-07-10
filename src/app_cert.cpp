// get_app_cert — fetch the Studio application cert (create_task's signing identity)
// from the Bambu cloud. See app_cert.hpp. Algorithm recovered from the stock plugin
// and validated live against api.bambulab.com (returns this account's exact app cert).

#include "obn/app_cert.hpp"

#include "obn/bbl_identity.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace obn::appcert {
namespace {

// Baked server wrap key: CN=service.bambulab.com, RSA-2048 (extracted from the stock
// plugin's .rdata). K is RSA-PKCS#1-v1.5-encrypted to this key as the aes256 query
// param so the cloud can recover K, GCM-decrypt the app identity, and encrypt the reply.
const char kServerPubKeyPem[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnbPBC80CMD2VB7Tqj9W/\n"
"olQscufbk0rvTqbINriL2WZvfCoBE1WLppJZ/E7cLP02SULh1gB0VuBwRRe4khwk\n"
"EFl2A87YaGdp4JRVbP+5xbYYJ09oECRdk0Mrnpo+p9jCW0iw0lxQi+rQ6ZsWwj3S\n"
"XzMpNDN3z/Mlx+byU4GkBt6vBsR4cJB8PFRak3KsC4YmWQNybGtoCPMFdCMDIxP6\n"
"Qr4o86qEkgK7lJc/ztYaXPDyx+t0uXsna+G1enNELru+2/q4Ppqqrl/Y5pHEdFTK\n"
"p4Nj9p2JYT1B5v1qaRExxCJQnQhAlnjANIw2ll7SC5cuSXks909Tbj0G7zofl4N/\n"
"kQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

// URL-safe base64 with '=' padding (matches the stock plugin's encAppKey/aes256).
std::string b64url(const uint8_t* p, size_t n) {
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string o; o.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t(p[i]) << 16) | (uint32_t(p[i + 1]) << 8) | p[i + 2];
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63]; o += T[(v >> 6) & 63]; o += T[v & 63];
    }
    if (n - i == 1) { uint32_t v = uint32_t(p[i]) << 16;
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63]; o += "=="; }
    else if (n - i == 2) { uint32_t v = (uint32_t(p[i]) << 16) | (uint32_t(p[i + 1]) << 8);
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63]; o += T[(v >> 6) & 63]; o += "="; }
    return o;
}

struct BioDel    { void operator()(BIO* b)            const { BIO_free(b); } };
struct PkeyDel   { void operator()(EVP_PKEY* p)       const { EVP_PKEY_free(p); } };
struct PctxDel   { void operator()(EVP_PKEY_CTX* p)   const { EVP_PKEY_CTX_free(p); } };
struct CctxDel   { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct X509Del   { void operator()(X509* p)           const { X509_free(p); } };

// AES-256-GCM seal -> nonce(12) ‖ ciphertext ‖ tag(16).
bool gcm_seal(const uint8_t K[32], const uint8_t nonce[12], const std::string& pt, std::string& out) {
    std::unique_ptr<EVP_CIPHER_CTX, CctxDel> c(EVP_CIPHER_CTX_new());
    if (!c) return false;
    if (EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(c.get(), nullptr, nullptr, K, nonce) != 1) return false;
    std::vector<uint8_t> ct(pt.size() + 16);
    int len = 0, ctlen = 0;
    if (EVP_EncryptUpdate(c.get(), ct.data(), &len, (const uint8_t*)pt.data(), (int)pt.size()) != 1) return false;
    ctlen = len;
    if (EVP_EncryptFinal_ex(c.get(), ct.data() + ctlen, &len) != 1) return false;
    ctlen += len;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) return false;
    out.assign((const char*)nonce, 12);
    out.append((const char*)ct.data(), (size_t)ctlen);
    out.append((const char*)tag, 16);
    return true;
}

// RSA PKCS#1 v1.5 public-encrypt K to the baked server key -> one 256-byte block.
bool rsa_wrap(const uint8_t K[32], std::string& out) {
    std::unique_ptr<BIO, BioDel> bio(BIO_new_mem_buf(kServerPubKeyPem, -1));
    if (!bio) return false;
    std::unique_ptr<EVP_PKEY, PkeyDel> pub(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if (!pub) return false;
    std::unique_ptr<EVP_PKEY_CTX, PctxDel> ctx(EVP_PKEY_CTX_new(pub.get(), nullptr));
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) != 1) return false;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1) return false;
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, K, 32) != 1) return false;
    out.resize(outlen);
    if (EVP_PKEY_encrypt(ctx.get(), (uint8_t*)out.data(), &outlen, K, 32) != 1) return false;
    out.resize(outlen);
    return true;
}

// cert_id = lower-hex of the leading serial bytes (x-bbl-app-certification-id,
// e.g. "4a63194e" for serial 4A63194E...). First 4 serial bytes.
std::string cert_id_from_pem(const std::string& pem) {
    std::unique_ptr<BIO, BioDel> bio(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    if (!bio) return {};
    std::unique_ptr<X509, X509Del> x(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!x) return {};
    const ASN1_INTEGER* s = X509_get0_serialNumber(x.get());
    if (!s || s->length <= 0 || !s->data) return {};
    int n = s->length < 4 ? s->length : 4;
    static const char H[] = "0123456789abcdef";
    std::string id;
    for (int i = 0; i < n; ++i) { id += H[(s->data[i] >> 4) & 0xF]; id += H[s->data[i] & 0xF]; }
    return id;
}

}  // namespace

AppCert fetch(const std::string& api_host, const std::string& access_token,
              const std::string& user_id, const std::string& app_identity) {
    AppCert r;
    if (access_token.empty() || app_identity.empty()) { r.error = "missing token or app_identity"; return r; }

    uint8_t K[32], nonce[12];
    if (RAND_bytes(K, 32) != 1 || RAND_bytes(nonce, 12) != 1) { r.error = "RAND_bytes failed"; return r; }

    std::string sealed;
    if (!gcm_seal(K, nonce, app_identity, sealed)) { r.error = "AES-256-GCM failed"; return r; }
    const std::string encAppKey = b64url((const uint8_t*)sealed.data(), sealed.size());

    std::string wrapped;
    if (!rsa_wrap(K, wrapped)) { r.error = "RSA wrap failed"; return r; }
    const std::string aes256 = b64url((const uint8_t*)wrapped.data(), wrapped.size());

    obn::http::Request req;
    req.method = obn::http::Method::GET;
    req.url    = api_host + "/v1/iot-service/api/user/applications/" + encAppKey +
                 "/cert?aes256=" + aes256 + "&ver=1";
    req.ordered_headers = obn::bbl::identity_headers(access_token, user_id,
                                                     /*client_id*/false, /*content_type*/false);
    auto resp = obn::http::perform(req);
    r.http_status = resp.status_code;
    if (!resp.error.empty())      { r.error = "transport: " + resp.error; return r; }
    if (resp.status_code != 200)  { r.error = "http " + std::to_string(resp.status_code) + ": " + resp.body.substr(0, 200); return r; }

    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) { r.error = "bad JSON: " + perr; return r; }
    if (root->find("code").as_int(0) != 0) {
        r.error = "cloud code=" + std::to_string(root->find("code").as_int()) + " " + root->find("message").as_string();
        return r;
    }
    r.cert_pem     = root->find("cert").as_string();
    r.key_blob_b64 = root->find("key").as_string();
    auto crlv = root->find("crl");
    r.crl = (crlv.is_array() && !crlv.as_array().empty()) ? crlv.as_array()[0].as_string() : crlv.as_string();
    if (r.cert_pem.empty()) { r.error = "reply has no cert: " + resp.body.substr(0, 200); return r; }
    r.cert_id = cert_id_from_pem(r.cert_pem);
    r.ok = true;
    OBN_INFO("get_app_cert: ok cert_id=%s (%zu B cert, key blob %zu B)",
             r.cert_id.c_str(), r.cert_pem.size(), r.key_blob_b64.size());
    return r;
}

}  // namespace obn::appcert
