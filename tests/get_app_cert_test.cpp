// Benign live test of the OSS get_app_cert (obn::appcert::fetch). Reads the token
// + app identity from the environment so no secret is compiled in. It performs a
// read-only authenticated cert fetch (the stock plugin does this every session).
//   BBL_TEST_TOKEN  cloud Bearer token   (required)
//   BBL_TEST_APPID  app_identity string  (required)
//   BBL_TEST_UID    account uid          (optional)
//   BBL_TEST_API    api host             (default https://api.bambulab.com)
#include "obn/app_cert.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

int main() {
    const char* api   = std::getenv("BBL_TEST_API");
    const char* tok   = std::getenv("BBL_TEST_TOKEN");
    const char* uid   = std::getenv("BBL_TEST_UID");
    const char* ident = std::getenv("BBL_TEST_APPID");
    if (!tok || !tok[0] || !ident || !ident[0]) {
        std::fprintf(stderr, "set BBL_TEST_TOKEN and BBL_TEST_APPID\n");
        return 2;
    }
    auto r = obn::appcert::fetch(api && api[0] ? api : "https://api.bambulab.com",
                                 tok, uid ? uid : "", ident);
    std::printf("ok=%d  http=%ld  cert_id=%s  err=%s\n",
                (int)r.ok, r.http_status, r.cert_id.c_str(), r.error.c_str());
    if (r.ok) {
        std::string head = r.cert_pem.substr(0, 64);
        std::printf("cert head: %s\n", head.c_str());
        std::printf("key blob : %zu bytes (K-wrapped app private key)\n", r.key_blob_b64.size());
    }
    return r.ok ? 0 : 1;
}
