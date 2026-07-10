#pragma once

// get_app_cert — fetch the Studio "application" certificate + private key that the
// Bambu cloud verifies create_task against (distinct from the slicer key). The
// request wraps a fresh symmetric key K to a baked server RSA key and GCM-encrypts
// the app-identity into the URL; the cloud replies with the app cert (plaintext),
// its CRL, and the app private key (K-wrapped). Algorithm recovered by RE of the
// stock plugin and validated live (returns this account's exact app cert).

#include <string>

namespace obn::appcert {

struct AppCert {
    bool         ok = false;
    long         http_status = 0;
    std::string  error;
    std::string  cert_pem;       // the app certificate (plaintext PEM from the reply)
    std::string  crl;            // the app CRL (plaintext PEM from the reply)
    std::string  cert_id;        // lower-hex of the leading serial bytes -> x-bbl-app-certification-id
    std::string  key_blob_b64;   // the "key" field verbatim: app private key, K-wrapped (not yet unwrapped)
};

// Perform get_app_cert.
//   api_host      e.g. "https://api.bambulab.com"
//   access_token  cloud Bearer token
//   user_id       account uid (for X-BBL-Client-ID; may be empty)
//   app_identity  ASCII "<appCertCN><appKeyToken>", account-specific (e.g. from
//                 BBL_APP_IDENTITY). Identifies which application cert to issue.
AppCert fetch(const std::string& api_host,
              const std::string& access_token,
              const std::string& user_id,
              const std::string& app_identity);

}  // namespace obn::appcert
