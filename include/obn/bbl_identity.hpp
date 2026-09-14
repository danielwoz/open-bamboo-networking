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
#include <map>
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

// Controls what the ordered identity block includes. Each field maps to one
// optional header; defaults reproduce the full genuine block. Callers pass the
// subset they need so the emitted set/order matches what they send today.
struct IdentityHeadersOptions {
    bool        include_client_id = false;  // X-BBL-Client-ID
    bool        with_content_type = true;   // trailing Content-Type
    bool        include_accept   = true;    // accept: application/json
    std::string client_name;                // X-BBL-Client-Name ("" = BambuStudio)
    std::string client_id_suffix;           // e.g. "obn0"; "" = per-request 4-hex
    // Tail headers appended in order after the identity block.
    std::vector<std::pair<std::string, std::string>> extra;
};

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

// Project an ordered header list to a std::map for the read/check convenience of
// legacy callers (e.g. `hdrs.find("Authorization")`). Order is lost (map sorts),
// but values/casing are preserved. Kept only for callers that inspect, not send.
inline std::map<std::string, std::string> as_map(const HeaderList& h)
{
    std::map<std::string, std::string> m;
    for (const auto& [k, v] : h) m[k] = v;
    return m;
}

// Build an ordered identity block for a caller that needs a leaner field set than
// the full genuine block. `opt` selects what's included/excluded so each caller
// reproduces its exact historical field set without changing behavior.
inline HeaderList identity_headers(const std::string& access_token,
                                 const std::string& user_id,
                                 const IdentityHeadersOptions& opt)
{
    auto h = identity_headers(access_token, user_id, opt.include_client_id,
                             opt.with_content_type);
    HeaderList out;
    out.reserve(h.size() + opt.extra.size());
    for (auto& kv : h) {
        const std::string& name = kv.first;
        if (name == "X-BBL-Client-ID")
            continue;  // rebuilt below so the caller's suffix (or a fresh one) is used
        if (name == "accept" && !opt.include_accept)
            continue;
        if (name == "Content-Type" && !opt.with_content_type)
            continue;
        if (name == "X-BBL-Client-Name" && !opt.client_name.empty())
            kv.second = opt.client_name;
        out.emplace_back(kv.first, kv.second);
    }
    if (opt.include_client_id && !user_id.empty()) {
        const std::string suffix = opt.client_id_suffix.empty()
                                    ? client_id_suffix() : opt.client_id_suffix;
        out.emplace_back("X-BBL-Client-ID", "slicer:" + user_id + ":" + suffix);
    }
    for (const auto& kv : opt.extra) out.emplace_back(kv.first, kv.second);
    return out;
}
}  // namespace obn::bbl
