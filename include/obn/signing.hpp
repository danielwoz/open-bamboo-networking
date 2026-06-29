#pragma once

// obn::signing — RSA-PKCS#1-v1.5 SHA-256 signing of print-command
// envelopes.
//
// Produces the {"header":{...},"print":{...}} object that non-Developer-
// Mode Bambu firmware requires for authenticated MQTT commands. Developer
// Mode printers do not validate the header, so callers that target only
// Developer Mode can omit it; this module is provided for completeness and
// for future use.
//
// Key resolution order (first hit wins):
//   1. Config::private_key_pem_path — path to a PEM file, or inline PEM text.
//   2. Environment variable BBL_SLICER_KEY — path or inline PEM text.
//   3. <BambuStudio config dir>/slicer_key.pem
//
// cert_id resolution order:
//   1. Config::cert_id
//   2. Environment variable BBL_SLICER_CERT_ID
//   3. <BambuStudio config dir>/slicer_cert_id.txt
//   4. Empty string (firmware will reject the command without a valid cert_id)
//
// All crypto goes through OpenSSL EVP_PKEY_* — no legacy RSA_* API.

#include <string>

namespace obn::signing {

// Configuration for the signing operation. All fields are optional;
// the module falls back through the resolution chain described above.
struct Config {
    // Path to an RSA PEM private key file.  May also be an inline PEM
    // blob (detected by the presence of "-----BEGIN ").
    std::string private_key_pem_path;
    // Verbatim cert_id to embed in the header.  When empty the module
    // falls back through env / file as described above.
    std::string cert_id;
};

struct SignResult {
    bool        ok            = false;
    std::string error;
    // On success: full {"header":{...},"print":{...}} envelope JSON
    // ready to be published on the MQTT topic.
    std::string envelope_json;
};

// Sign `print_json` (a {"print":{...}} object produced by print_job) and
// return the wrapped signed envelope.
//
// The inner print object's keys are sorted for canonical signing before
// the signature is computed, matching the stock plugin's behaviour.
//
// Returns ok=false with a diagnostic in `error` when no private key can
// be resolved, or when the signing operation itself fails.
SignResult sign_print_command(const std::string& print_json,
                              const Config& cfg = {});

} // namespace obn::signing
