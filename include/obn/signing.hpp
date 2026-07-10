#pragma once

#include <string>

namespace obn::signing {

// Returns a signed envelope JSON for {"print":{...}} payloads.
// All other message types pass through unchanged.
// If printer_model is provided and identifies an H2D, nozzleId values in
// ams_mapping_info are flipped 0↔1 before signing.
std::string maybe_sign(const std::string& payload_json,
                       const std::string& printer_model = {});

// Signs raw bytes with the slicer key.
// Returns the base64-encoded RSA-PKCS#1 v1.5 + SHA-256 signature.
std::string sign_bytes(const std::string& data);

// Computes the x-bbl-device-security-sign header value for cloud REST
// requests: a raw RSA PKCS#1 v1.5 signature (no hash) over the current Unix
// time in milliseconds, base64-encoded. Matches the proprietary plugin, which
// signs a fresh timestamp (not the request body) for replay protection.
std::string device_security_sign();

// Standard base64 encoding (RFC 4648, with padding).
std::string base64_encode(const unsigned char* data, std::size_t len);

// Returns the cert_id string used in envelope headers and REST auth headers.
// Priority: BBL_SLICER_CERT_ID env > slicer_cert_id.txt alongside the key file.
// Returns empty string if neither is configured.
const std::string& slicer_cert_id();

// App cert_id + app-key timestamp signature for create_task. The cloud verifies
// these against the get_app_cert-issued application certificate (the slicer key
// yields HTTP 403 on create_task). App key: BBL_APP_KEY_PEM / app_key.pem alongside
// the slicer key; cert_id: BBL_APP_CERT_ID / app_cert_id.txt.
const std::string& app_cert_id();
std::string        device_security_sign_app();

} // namespace obn::signing
