#pragma once

// Genuine-parity cloud REST identity headers.
//
// Cloudflare (in front of api.bambulab.com) fingerprints requests on header
// ORDER and CASING (JA4H), so the header list must be sent VERBATIM in the exact
// order the stock plugin + Studio emit. This reproduces that block, captured live
// on Windows (BambuSlicerKeySaver win/host/cloud_tap.cpp) and Linux (MITM).
//
// Returned as an ordered vector; assign to obn::http::Request::ordered_headers so
// obn::http::perform sends it verbatim (no sort, no default UA/Accept/CType).
//
// Values are OS-aware and env-overridable:
//   BBL_AGENT_VERSION  BBL_CLIENT_VERSION  BBL_DEVICE_ID  BBL_LANGUAGE
//   BBL_OS_TYPE  BBL_OS_VERSION  BBL_EXEC_INFO

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace obn::bbl {

using HeaderList = std::vector<std::pair<std::string, std::string>>;

// Per-request 4-hex suffix for X-BBL-Client-ID (genuine changes it per request).
// Not cryptographic; the value is volatile + masked in diffs, only the FORMAT
// slicer:<uid>:<4hex> matters.
inline std::string client_id_suffix()
{
    static std::atomic<unsigned> ctr{0x1a2b};
    unsigned v = (ctr.fetch_add(0x9e37u) ) & 0xffffu;
    char b[8]; std::snprintf(b, sizeof b, "%04x", v);
    return b;
}

inline std::string env_or(const char* k, const char* d)
{
    const char* v = std::getenv(k);
    return std::string(v && v[0] ? v : d);
}

// include_client_id: genuine sends X-BBL-Client-ID only on POST + single-resource
//                    GETs (task/<id>, consent), not on list GETs / get_app_cert.
// with_content_type: genuine sends Content-Type on most calls but NOT get_app_cert.
inline HeaderList identity_headers(const std::string& access_token,
                                   const std::string& user_id,
                                   bool include_client_id,
                                   bool with_content_type)
{
#if defined(_WIN32)
    const std::string os_type   = env_or("BBL_OS_TYPE",    "windows");
    const std::string os_ver    = env_or("BBL_OS_VERSION", "10.0.26200");
    // Genuine Windows Studio sends its EXE's Authenticode cert descriptor here;
    // verify_result "0" == a genuine signed build. Constant per Studio release.
    const std::string exec_info = env_or("BBL_EXEC_INFO",
        "{\"cert_end_date\":\"2029-03-12\",\"cert_start_date\":\"2025-12-23\","
        "\"hash_value\":\"3dca1e74c49cdcd6b6f551500f6f7667af28d8db\","
        "\"issue_name\":\"GlobalSign GCC R45 EV CodeSigning CA 2020\","
        "\"serial_number\":\"23009bd87d891a5405b02fbc\","
        "\"sign_date\":\"2026-06-01T17:16:16Z\","
        "\"subject_name\":\"Shanghai Lunkuo Technology Co., Ltd\","
        "\"verify_result\":\"0\"}");
#else
    const std::string os_type   = env_or("BBL_OS_TYPE",    "linux");
    const std::string os_ver    = env_or("BBL_OS_VERSION", "5.15.0");
    const std::string exec_info = env_or("BBL_EXEC_INFO",  "{}");
#endif
    const std::string agent_ver  = env_or("BBL_AGENT_VERSION",  "02.07.01.51");
    const std::string client_ver = env_or("BBL_CLIENT_VERSION", "02.07.01.57");
    const std::string device_id  = env_or("BBL_DEVICE_ID", "887b3544-9221-4b48-9838-cc01c35e6e8d");
    const std::string language   = env_or("BBL_LANGUAGE",  "en-US");

    HeaderList h;
    h.reserve(17);
    h.emplace_back("User-Agent", "bambu_network_agent/" + agent_ver);
    if (include_client_id && !user_id.empty())
        h.emplace_back("X-BBL-Client-ID", "slicer:" + user_id + ":" + client_id_suffix());
    h.emplace_back("X-BBL-Client-Name",     "BambuStudio");
    h.emplace_back("X-BBL-Client-Type",     "slicer");
    h.emplace_back("X-BBL-Client-Version",  client_ver);
    h.emplace_back("X-BBL-Device-ID",       device_id);
    h.emplace_back("X-BBL-Language",        language);
    h.emplace_back("X-BBL-OS-Type",         os_type);
    h.emplace_back("X-BBL-OS-Version",      os_ver);
    h.emplace_back("X-BBL-Agent-Version",   agent_ver);
    h.emplace_back("X-BBL-Executable-info", exec_info);
    h.emplace_back("X-BBL-Agent-OS-Type",   os_type);
    h.emplace_back("X-BBL-Executable-Env",  "false");
    h.emplace_back("accept",                "application/json");
    h.emplace_back("Authorization",         "Bearer " + access_token);
    if (with_content_type)
        h.emplace_back("Content-Type",      "application/json");
    return h;
}

}  // namespace obn::bbl
