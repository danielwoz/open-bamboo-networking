// Cloud print pipeline.
//
// Reverse-engineered from a MITM capture of Studio 02.05.02.51 + the
// original closed-source Bambu plugin pushing a job through
// "start_local_print_with_record" (which is what Studio picks whenever
// the printer is reachable on the LAN and an access code is known -
// the bare "start_print" path we still share all the HTTP plumbing
// with, only the final delivery channel changes).
//
// End-to-end sequence for a single plate:
//
//   [A]  POST   /v1/iot-service/api/user/project                body {"name":"<job>"}
//        -> { project_id, model_id, profile_id, upload_url,
//             upload_ticket }                                     << [A1]
//   [B]  PUT    <upload_url from A1>                              config 3mf
//   [C]  PUT    /v1/iot-service/api/user/notification             notify
//   [D]  GET    /v1/iot-service/api/user/notification?action=upload&ticket=..
//   [E]  PATCH  /v1/iot-service/api/user/project/<pid>            {"profile_id","profile_print_3mf":[{..,"url":"ftp://..."}]}
//   [F]  GET    /v1/iot-service/api/user/upload?models=<mid>_<plate>.3mf
//        -> { urls: [{ url }] }                                   << [F1]
//   [G]  PUT    <F1 url>                                          full 3mf with gcode
//   [H]  PATCH  /v1/iot-service/api/user/project/<pid>            register real url
//   [I]  POST   /v1/user-service/my/task                          {..,"mode":"lan_file"/"cloud_file"}
//        -> { id: <task_id> }                                     << [I1]
//   [J]  MQTT publish project_file on the appropriate channel.
//
// In the LAN-channel ("start_local_print_with_record") variant we also
// push the .3mf to the printer (:6000 emmc cache on brtc hardware, else
// FTPS STOR); the cloud record exists for MakerWorld task history.
//
// Anything that needs to be kept in sync with Studio's internal
// format is commented inline rather than factored out, because small
// field-name drifts here break the flow silently (the printer either
// refuses the MQTT, or the cloud server 500s the create_task call,
// and neither surface a helpful error to the user).

#include "obn/agent.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/signing.hpp"
#include "obn/app_cert.hpp"
#include "obn/bbl_identity.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/print_job.hpp"
#include "obn/print_params_ftp_prefs.hpp"
#include "obn/tunnel_upload.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace obn {

namespace {

// Compact JSON array escape helper reused from the LAN path.
std::string json_escape(const std::string& in)
{
    return obn::json::escape(in);
}

// Redacts a presigned URL for logging: keeps scheme://host/path and the
// query-parameter *names* (so we can tell a SigV4 PUT-presign apart from a
// GET-presign, spot an expiry, etc.) but drops every query *value* Ã¢â‚¬â€ the
// AWS signature and any embedded token must never hit the log. A trailing
// "?<k1>=Ã¢â‚¬Â¦&<k2>=Ã¢â‚¬Â¦" summary is appended so the shape stays diagnosable.
std::string redact_url(const std::string& url)
{
    const auto q = url.find('?');
    if (q == std::string::npos) return url;
    std::string out = url.substr(0, q);
    out += " ?[";
    std::size_t i = q + 1;
    bool first = true;
    while (i < url.size()) {
        std::size_t amp = url.find('&', i);
        std::size_t end = (amp == std::string::npos) ? url.size() : amp;
        std::size_t eq  = url.find('=', i);
        std::string key = (eq != std::string::npos && eq < end)
                              ? url.substr(i, eq - i)
                              : url.substr(i, end - i);
        if (!first) out += ',';
        out += key;
        first = false;
        if (amp == std::string::npos) break;
        i = amp + 1;
    }
    out += ']';
    return out;
}

// Reads the whole file into memory. The print-ready 3mf is typically
// a few MB up to ~100 MB; config 3mf is always <200KB. We keep a
// single buffer in memory for both because libcurl's PUT path wants
// the data in one shot (CURLOPT_POSTFIELDS). If we ever need to
// stream multi-GB uploads, the right fix is a read-callback variant
// of obn::http::Request, not chunking here.
std::string slurp_file(const std::string& path, std::string* err)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        if (err) *err = "open failed";
        return {};
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    if (!ifs && !ifs.eof()) {
        if (err) *err = "read failed";
        return {};
    }
    return oss.str();
}

// AMS mapping helpers. Studio hands us the mapping as a JSON array
// string in params.ams_mapping ("[0,-1,-1,-1]") and richer info in
// params.ams_mapping2 / ams_mapping_info. We pass them through
// verbatim when they look like valid JSON; otherwise fall back to
// a conservative empty mapping.

std::string trim(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

std::string json_or_default(const std::string& raw, const char* fallback)
{
    std::string s = trim(raw);
    if (s.empty()) return fallback;
    // Cheap validator: accept only strings that look like a JSON
    // array/object (first char). json::parse would be stricter but
    // also much slower; the mapping strings come from Studio's own
    // serializer, so a sniff is enough.
    if (s.front() == '[' || s.front() == '{') return s;
    return fallback;
}

// Build a single amsMapping2 element as the server expects it:
// `{"amsId":N,"slotId":M}` (camelCase). The convention observed in
// the MITM dump is:
//   -1   -> amsId=255, slotId=0 (unset / "external spool" sentinel)
//   >=0  -> amsId=i/4, slotId=i%4 (linear index over AMS slot 0..3)
// The external-spool sentinel is `{amsId:255,slotId:0}`, NOT
// `{...,slotId:255}`: a genuine no-AMS /my/task body carries slotId 0
// and the endpoint 400s on the wrong shape (cross-validated in #48).
std::string ams_slot_pair(int ams_id, int slot_id)
{
    return "{\"amsId\":" + std::to_string(ams_id) +
           ",\"slotId\":" + std::to_string(slot_id) + "}";
}

// Produce the amsMapping2 JSON array for /my/task.
//
// Studio *does* hand us a p.ams_mapping2 string, but it's serialized
// with snake_case keys (`ams_id`, `slot_id`) as used by the printer's
// internal MQTT schema. The cloud `/my/task` endpoint only accepts
// camelCase (`amsId`, `slotId`) and 400s with
// `field "amsMapping2[0].amsId" is not set` otherwise.
//
// We therefore parse Studio's JSON ourselves and re-serialize into the
// camelCase shape. If that fails or Studio gave us nothing usable, we
// fall back to deriving the mapping from the flat p.ams_mapping array
// (`[0,-1,2,-1]`).
std::string ams_mapping2_for_cloud(const BBL::PrintParams& p)
{
    auto derived_from_flat = [&]() {
        auto root = obn::json::parse(p.ams_mapping);
        if (!root || !root->is_array()) return std::string("[]");
        std::string out = "[";
        bool first = true;
        for (const auto& v : root->as_array()) {
            if (!v.is_number()) continue;
            int idx = static_cast<int>(v.as_number());
            int ams_id, slot_id;
            if (idx < 0) { ams_id = 255; slot_id = 0; }
            else         { ams_id = idx / 4; slot_id = idx % 4; }
            if (!first) out.push_back(',');
            first = false;
            out += ams_slot_pair(ams_id, slot_id);
        }
        out.push_back(']');
        return out;
    };

    std::string raw = trim(p.ams_mapping2);
    if (raw.empty() || raw == "[]") return derived_from_flat();

    auto root = obn::json::parse(raw);
    if (!root || !root->is_array()) return derived_from_flat();

    std::string out = "[";
    bool first = true;
    for (const auto& item : root->as_array()) {
        // Accept either schema. Prefer camelCase if present (future-
        // proof against Studio catching up), otherwise snake_case.
        auto ams_v  = item.find("amsId");
        if (!ams_v.is_number())  ams_v  = item.find("ams_id");
        auto slot_v = item.find("slotId");
        if (!slot_v.is_number()) slot_v = item.find("slot_id");
        int ams_id  = ams_v.is_number()  ? static_cast<int>(ams_v.as_number())  : 255;
        // Missing slot defaults to 0 to match the external-spool sentinel
        // {amsId:255,slotId:0} (see ams_slot_pair note; #48).
        int slot_id = slot_v.is_number() ? static_cast<int>(slot_v.as_number()) : 0;
        if (!first) out.push_back(',');
        first = false;
        out += ams_slot_pair(ams_id, slot_id);
    }
    out.push_back(']');
    return out;
}

std::string to_bool(bool v) { return v ? "true" : "false"; }

// ---------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------

// Compile-time OS identity for X-BBL-OS-Type. The MakerWorld POST /my/task
// endpoint validates this against the OS the content was uploaded from and
// rejects a mismatch with HTTP 403, so it must reflect the real platform
// (an earlier hard-coded "linux" broke Windows/macOS cloud prints).
constexpr const char* kOsType =
#if defined(_WIN32)
    "windows";
#elif defined(__APPLE__)
    "macos";
#else
    "linux";
#endif

// Shared X-BBL headers captured from the stock plugin. Cloudflare
// in front of api.bambulab.com is lenient about missing X-BBL
// fields, but POST /my/task enforces two by VALUE: X-BBL-Client-Name
// (must be "BambuStudio" to access the uploaded content) and
// X-BBL-OS-Type (must match the uploader's OS). See config::client_name.
std::map<std::string, std::string> bbl_headers(const std::string& access_token,
                                               const std::string& user_id)
{
    const auto& cfg_client_name = obn::config::current().client_name;
    std::map<std::string, std::string> h;
    h["Authorization"]        = "Bearer " + access_token;
    h["Content-Type"]         = "application/json";
    h["Accept"]               = "application/json";
    // Default to genuine Bambu Studio's cloud fingerprint so the REST identity
    // headers match the stock plugin (OrcaSlicer's host agent sends "BambuStudio"
    // via BBLCloudServiceAgent::get_extra_header, and the stock network plugin
    // sends the same on every api.bambulab.com call). Still overridable through
    // config for callers that want to identify differently.
    h["X-BBL-Client-Name"]    = cfg_client_name.empty() ? std::string{"BambuStudio"}
                                                        : cfg_client_name;
    h["X-BBL-Client-Type"]    = "slicer";
    h["X-BBL-OS-Type"]        = kOsType;
    h["X-BBL-Agent-OS-Type"]  = kOsType;
    h["X-BBL-Language"]       = "en-US";
    // Genuine Studio sends a JSON executable fingerprint here, NOT "{}". The
    // exact key set is only known from a live MITM capture of the stock plugin
    // (NETWORK_PLUGIN.md notes the header exists but not its bytes). This mirrors
    // the shape (product / version / os) using the current Studio release string
    // so the cloud version gate does not flag us as outdated. TODO: replace with
    // the byte-exact blob captured from the genuine plugin via bambu_host.
    h["X-BBL-Executable-info"]= "{\"name\":\"BambuStudio\",\"version\":\"02.07.01.62\",\"os\":\"windows\"}";
    if (!user_id.empty())
        h["X-BBL-Client-ID"] = "slicer:" + user_id + ":obn0";
    return h;
}

bool status_ok(long code) { return code >= 200 && code < 300; }

// Reports a transport or HTTP error through Studio's update_fn and
// stashes the server message where our log scraper can see it.
int fail_stage(BBL::OnUpdateStatusFn update_fn, int code, const std::string& what,
               const obn::http::Response& resp)
{
    std::string detail = what;
    if (!resp.error.empty()) detail += ": " + resp.error;
    else if (resp.status_code != 0)
        detail += ": HTTP " + std::to_string(resp.status_code);
    OBN_ERROR("cloud_print: %s (body=%.2000s)", detail.c_str(), resp.body.c_str());
    if (update_fn) update_fn(BBL::PrintingStageERROR, code, detail);
    return code;
}

// ---------------------------------------------------------------
// Per-step HTTP calls
// ---------------------------------------------------------------

struct ProjectInfo {
    std::string project_id;
    std::string model_id;
    std::string profile_id;
    std::string upload_url;     // presigned S3 PUT for the config 3mf (step B)
    std::string upload_ticket;  // fed back into the notification endpoint
};

int create_project(const std::string& api, const std::string& token,
                   const std::string& user_id,
                   const std::string& name, ProjectInfo* out,
                   BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method  = obn::http::Method::POST;
    req.url     = api + "/v1/iot-service/api/user/project";
    req.ordered_headers = obn::bbl::identity_headers(token, user_id, /*client_id*/true, /*content_type*/true);
    req.body    = std::string("{\"name\":") + json_escape(name) + "}";
    req.timeout_s = 30;

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                          "create_project", resp);

    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        OBN_ERROR("cloud_print: create_project bad JSON: %s (body=%s)",
                  perr.c_str(), resp.body.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                                 "bad JSON");
        return BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED;
    }
    out->project_id    = root->find("project_id").as_string();
    out->model_id      = root->find("model_id").as_string();
    out->profile_id    = root->find("profile_id").as_string();
    out->upload_url    = root->find("upload_url").as_string();
    out->upload_ticket = root->find("upload_ticket").as_string();

    if (out->project_id.empty() || out->upload_url.empty()) {
        OBN_ERROR("cloud_print: create_project missing fields: body=%s",
                  resp.body.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                                 "missing fields");
        return BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED;
    }
    OBN_INFO("cloud_print: project pid=%s mid=%s prof=%s",
             out->project_id.c_str(), out->model_id.c_str(), out->profile_id.c_str());
    OBN_DEBUG("cloud_print: config upload_url=%s", redact_url(out->upload_url).c_str());
    return 0;
}

// PUT bytes to a presigned S3 URL. Amazon's signature covers only the
// method + resource + expiry + AWS key; query-string presigned URLs
// are forgiving of extra headers, which is why the original plugin
// blithely sends its X-BBL-* set on them too. We mimic that.
int s3_put(const std::string& url, const std::string& body,
           BBL::OnUpdateStatusFn update_fn,
           BBL::WasCancelledFn   cancel_fn,
           int                   stage_start_pct,
           int                   stage_end_pct,
           int                   err_code)
{
    (void)cancel_fn; // libcurl synchronous path: we observe cancel on the
                     // next major step boundary.
    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = url;
    // The Bambu cloud presigner returns an S3 signature-V2 query-auth URL
    // (`?AWSAccessKeyId=Ã¢â‚¬Â¦&Expires=Ã¢â‚¬Â¦&Signature=Ã¢â‚¬Â¦`), confirmed on-wire
    // against genuine POST /user/project traffic (us-west-2, 2026-07).
    // NOT SigV4 Ã¢â‚¬â€ there is no X-Amz-Algorithm / X-Amz-Signature. The V2
    // StringToSign covers Content-Type, and the presigner signs with an
    // empty one, so we MUST send the PUT without a Content-Type or the
    // signature will not match. Two catches:
    //   * libcurl, when doing a PUT via CUSTOMREQUEST+POSTFIELDS, silently
    //     injects `Content-Type: application/x-www-form-urlencoded`. The
    //     idiomatic way to tell libcurl to drop a header is to append
    //     the header name followed by a colon and NO value.
    //   * libcurl also auto-adds `Expect: 100-continue` for bodies > 1 KiB;
    //     Studio's original plugin omits it, so we do the same.
    req.no_default_content_type = true; // don't add our own application/json
    req.no_default_accept       = true; // don't add our own Accept: application/json
    req.headers["Content-Type"] = "";   // REMOVE libcurl's auto Content-Type
    req.headers["Expect"]       = "";   // REMOVE libcurl's auto Expect: 100-continue
    req.body      = body;
    req.timeout_s = 120;

    if (update_fn && stage_start_pct >= 0)
        update_fn(BBL::PrintingStageUpload, stage_start_pct,
                  std::to_string(stage_start_pct) + "%");

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, err_code, "s3 PUT", resp);

    OBN_DEBUG("cloud_print: s3 PUT ok http=%ld bytes=%zu url=%s",
              resp.status_code, body.size(), redact_url(url).c_str());

    if (update_fn && stage_end_pct >= 0)
        update_fn(BBL::PrintingStageUpload, stage_end_pct,
                  std::to_string(stage_end_pct) + "%");
    return 0;
}

int notify_upload(const std::string& api, const std::string& token,
                  const std::string& user_id,
                  const std::string& ticket, const std::string& origin_name,
                  BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = api + "/v1/iot-service/api/user/notification";
    req.ordered_headers = obn::bbl::identity_headers(token, user_id, /*client_id*/true, /*content_type*/true);
    std::ostringstream os;
    os << "{\"upload\":{\"origin_file_name\":" << json_escape(origin_name)
       << ",\"ticket\":" << json_escape(ticket) << "}}";
    req.body    = os.str();
    req.timeout_s = 30;
    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_PUT_NOTIFICATION_FAILED,
                          "notify_upload", resp);
    return 0;
}

// Polls /notification?action=upload until the async upload settles.
// HTTP is always 200; the body is {"message":"running"|"success", ...}.
// Keep polling while message=="running"; "success" ends the wait. Any
// other message is a hard failure.
int poll_upload(const std::string& api, const std::string& token,
                const std::string& user_id,
                const std::string& ticket,
                BBL::OnUpdateStatusFn update_fn,
                BBL::WasCancelledFn cancel_fn)
{
    // Content-Type=true: genuine sends it on all requests except get_app_cert and
    // task/<id>; these upload-flow GETs are neither. flag inferred (no capture).
    auto ohdrs = obn::bbl::identity_headers(token, user_id, /*client_id*/false, /*content_type*/true);
    const std::string url = api
        + "/v1/iot-service/api/user/notification?action=upload&ticket="
        + obn::http::url_encode(ticket);

    for (int attempt = 0; attempt < 20; ++attempt) {
        if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;
        obn::http::Request greq;
        greq.method          = obn::http::Method::GET;
        greq.url             = url;
        greq.ordered_headers = ohdrs;
        auto resp = obn::http::perform(greq);
        if (!resp.error.empty() || !status_ok(resp.status_code)) {
            OBN_DEBUG("cloud_print: poll_upload attempt=%d status=%ld err=%s",
                      attempt, resp.status_code, resp.error.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        auto root = obn::json::parse(resp.body);
        const std::string msg = root ? root->find("message").as_string()
                                     : std::string{};
        if (msg == "running") {
            OBN_DEBUG("cloud_print: poll_upload running attempt=%d", attempt);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        // The genuine poll response carries no explicit message; a 2xx without
        // an explicit "running" means the upload finished.
        if (msg.empty() || msg == "success") {
            OBN_DEBUG("cloud_print: poll_upload OK attempt=%d", attempt);
            return 0;
        }
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_FAILED,
                          "poll_upload", resp);
    }
    if (update_fn) update_fn(BBL::PrintingStageERROR,
                             BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_TIMEOUT,
                             "upload poll timeout");
    return BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_TIMEOUT;
}

// PATCH /project/<pid> with the profile_print_3mf descriptor that
// points at where the print-ready 3mf now lives. Studio issues this
// twice - once with a throw-away ftp:// placeholder before the real
// OSS upload, once more with the real URL afterwards. We copy that
// pattern because the server-side state machine seems to care about
// the first call being present.
int patch_project(const std::string& api, const std::string& token,
                  const std::string& user_id,
                  const std::string& project_id,
                  const std::string& profile_id,
                  const std::string& md5, int plate_idx,
                  const std::string& url,
                  BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method    = obn::http::Method::PATCH;
    req.url       = api + "/v1/iot-service/api/user/project/" + project_id;
    req.ordered_headers = obn::bbl::identity_headers(token, user_id, /*client_id*/true, /*content_type*/true);
    req.timeout_s = 30;
    std::ostringstream os;
    os << "{\"profile_id\":" << json_escape(profile_id)
       << ",\"profile_print_3mf\":[{"
       << "\"md5\":" << json_escape(md5)
       << ",\"plate_idx\":" << (plate_idx <= 0 ? 1 : plate_idx)
       << ",\"url\":" << json_escape(url)
       << "}]}";
    req.body = os.str();

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_PATCH_PROJECT_FAILED,
                          "patch_project", resp);
    return 0;
}

int get_upload_url(const std::string& api, const std::string& token,
                   const std::string& user_id,
                   const std::string& model_slot,
                   std::string* out_url,
                   BBL::OnUpdateStatusFn update_fn)
{
    // Content-Type=true: genuine sends it on all requests except get_app_cert and
    // task/<id>; these upload-flow GETs are neither. flag inferred (no capture).
    auto ohdrs = obn::bbl::identity_headers(token, user_id, /*client_id*/false, /*content_type*/true);
    std::string url = api + "/v1/iot-service/api/user/upload?models="
                    + obn::http::url_encode(model_slot);
    obn::http::Request greq; greq.method = obn::http::Method::GET; greq.url = url; greq.ordered_headers = ohdrs;
    auto resp = obn::http::perform(greq);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url", resp);
    // Raw body holds only presigned URLs + object keys (no account secrets);
    // kept at DEBUG for diagnosing endpoint shape changes.
    OBN_DEBUG("cloud_print: get_upload_url raw body=%s", resp.body.c_str());
    auto root = obn::json::parse(resp.body);
    if (!root) return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                                 "bad get_upload_url JSON", resp);
    auto arr_v = root->find("urls");
    const auto& arr = arr_v.as_array();
    if (arr.empty())
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url empty", resp);
    auto url_v = arr.front().find("url");
    *out_url = url_v.as_string();
    if (out_url->empty())
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url missing url", resp);
    OBN_DEBUG("cloud_print: get_upload_url -> %s", redact_url(*out_url).c_str());
    return 0;
}

// The body of POST /my/task is the single biggest surface we have to
// mimic from Studio. It is 27 fields; most map 1:1 to PrintParams. Fields we
// can't reconstruct ourselves are forwarded verbatim from PrintParams (the
// slicer fills them); they fall back to an empty array only when the caller
// left them blank.
//
// Cloud contract for the nozzle / filament-mapping fields (single- vs
// dual-nozzle, e.g. H2D):
//   * nozzleInfos comes from p.nozzles_info. Single-nozzle: []. Dual-nozzle:
//     one object per nozzle, e.g.
//       [{"diameter":0.4,"flowSize":"standard_flow","id":1,"type":null},
//        {"diameter":0.4,"flowSize":"standard_flow","id":0,"type":null}]
//     (id 1 = left, id 0 = right). We forward it as-is.
//   * amsDetailMapping comes from p.ams_mapping_info. On dual-nozzle each entry
//     also carries a "nozzleId" (0 = right, 1 = left) identifying which nozzle
//     the filament feeds; single-nozzle entries omit it. Forwarded as-is.
//   * amsMapping2 is the [{amsId,slotId}] form (255 = external/none). We prefer
//     p.ams_mapping2 (which preserves external-spool slots like {255,0}) and
//     only derive it from the flat amsMapping when ams_mapping2 is blank -- the
//     flat form collapses -1 to {255,255} and would lose that slot info.
//   A standalone (non-slicer) caller that builds PrintParams itself MUST
//   populate nozzles_info / ams_mapping_info / ams_mapping2 for a dual-nozzle
//   printer; we cannot synthesize them without the printer's nozzle layout.
//
// Cloud contract for the model-identity fields:
//   * modelId / profileId are the freshly uploaded instance, minted by the
//     preceding upload pipeline (create_project -> upload -> confirm). The task
//     binds to this instance, so it must be a real, confirmed asset the account
//     owns. Reusing an arbitrary or unconfirmed id yields HTTP 403 ("no access
//     to the content"). These come from `model_id`/`profile_id` here, not from
//     PrintParams.
//   * oriModelId / oriProfileId identify the SOURCE design a model was derived
//     from. Two valid cases:
//       - Online-sourced model (e.g. MakerWorld): oriModelId/oriProfileId are
//         the source design ids, taken from the 3mf's DesignModelId/
//         DesignProfileId metadata (p.origin_model_id/origin_profile_id).
//       - Locally-authored model: it has no source design, so oriModelId is ""
//         and oriProfileId is 0. The cloud accepts this and creates the task
//         against the uploaded modelId alone. No design linkage is required.
//   * Request auth: x-bbl-device-security-sign is raw PKCS#1 v1.5 over the
//     current epoch-ms timestamp with the slicer key; x-bbl-app-certification-id
//     names the cert as CN=<issuer>:<serial> (see create_task).
std::string build_task_body(const BBL::PrintParams& p,
                            const std::string& project_id,
                            const std::string& model_id,
                            const std::string& profile_id,
                            bool use_lan_channel)
{
    (void)project_id;
    std::ostringstream os;
    os << "{";
    // Forwarded as-is; on dual-nozzle each entry carries a nozzleId (see contract).
    os << "\"amsDetailMapping\":"
       << json_or_default(p.ams_mapping_info, "[]");
    os << ",\"amsMapping\":"  << json_or_default(p.ams_mapping, "[-1]");
    os << ",\"amsMapping2\":" << ams_mapping2_for_cloud(p);
    if (!p.nozzle_mapping.empty()) {
        os << ",\"nozzleMapping\":" << p.nozzle_mapping;
    }
    os << ",\"autoBedLeveling\":"     << p.auto_bed_leveling;
    os << ",\"bedLeveling\":"         << to_bool(p.task_bed_leveling);
    os << ",\"bedType\":" << json_escape(p.task_bed_type.empty()
                                         ? std::string{"auto"} : p.task_bed_type);

    int cfg_bits = 0;
    #if ABI_VERSION >= 0x020503
        if (p.task_timelapse_use_internal &&
            !obn::config::current().force_timelapse_external)
            cfg_bits |= 4;
    #endif
    os << ",\"cfg\":\"" << cfg_bits << "\"";
    os << ",\"cover\":\"\""; // TODO: investigate 
    os << ",\"deviceId\":"     << json_escape(p.dev_id);
    os << ",\"extrudeCaliFlag\":"         << p.auto_flow_cali;
    // Genuine bodies always carry extrudeCaliManualMode; default it to 0 on
    // ABIs that predate the struct field.
    #if ABI_VERSION >= 0x020400
        os << ",\"extrudeCaliManualMode\":"   << p.extruder_cali_manual_mode;
    #else
        os << ",\"extrudeCaliManualMode\":0";
    #endif
    os << ",\"filamentSettingIds\":[]"; // TODO: investigate 
    os << ",\"flowCali\":"            << to_bool(p.task_flow_cali);
    os << ",\"layerInspect\":"        << to_bool(p.task_layer_inspect);
    os << ",\"mode\":"
       << (use_lan_channel ? std::string{"\"lan_file\""}
                           : std::string{"\"cloud_file\""});
    os << ",\"modelId\":"     << json_escape(model_id);
    // [] on single-nozzle; one object per nozzle on dual-nozzle (see contract).
    os << ",\"nozzleInfos\":" << json_or_default(p.nozzles_info, "[]");
    os << ",\"nozzleOffsetCali\":"    << p.auto_offset_cali;
    os << ",\"oriModelId\":"  << json_escape(p.origin_model_id);
    os << ",\"oriProfileId\":" << p.origin_profile_id;
    os << ",\"plateIndex\":"  << (p.plate_index <= 0 ? 1 : p.plate_index);
    // profileId must be a number in the MITM baseline.
    os << ",\"profileId\":"   << (profile_id.empty() ? std::string{"0"} : profile_id);
    os << ",\"sequence_id\":\"20000\""; // TODO: is it always 20000?
    os << ",\"timelapse\":"   << to_bool(p.task_record_timelapse);
    os << ",\"title\":"       << json_escape(p.project_name.empty()
                                             ? p.task_name : p.project_name);
    os << ",\"useAms\":"      << to_bool(p.task_use_ams);
    os << ",\"vibrationCali\":" << to_bool(p.task_vibration_cali);
    os << "}";
    return os.str();
}

int create_task(const std::string& api, const std::string& token,
                const std::string& user_id,
                const std::string& body, std::string* out_task_id,
                BBL::OnUpdateStatusFn update_fn)
{
    // MakerWorld's /my/task endpoint is picky about amsMapping2 /
    // amsDetailMapping field shape; log the full body so we can diff
    // against the MITM dump when it 400s.
    OBN_DEBUG("cloud_print: create_task body=%s", body.c_str());
    obn::http::Request req;
    req.method  = obn::http::Method::POST;
    req.url     = api + "/v1/user-service/my/task";
    auto ohdrs = obn::bbl::identity_headers(token, user_id, /*client_id*/true, /*content_type*/true);
    // create_task is verified against the app certificate, which shares the
    // slicer key pair -- the genuine x-bbl-device-security-sign RSA-recovers
    // against the slicer public key over the current epoch-ms timestamp. The
    // header names the cert by issuer CN + serial ("CN=<issuer>:<serial>"). When
    // BBL_APP_IDENTITY is set, refresh the cert via get_app_cert to obtain that
    // id; else fall back to the configured app_cert_id().
    std::string app_id = obn::signing::app_cert_id();
    if (const char* ident = std::getenv("BBL_APP_IDENTITY"); ident && ident[0]) {
        auto ac = obn::appcert::fetch(api, token, user_id, ident);
        if (ac.ok) { app_id = ac.cert_id;
            OBN_INFO("create_task: app cert refreshed via get_app_cert (cert_id=%s)", ac.cert_id.c_str()); }
        else OBN_WARN("create_task: get_app_cert failed (%s); using configured app_cert_id", ac.error.c_str());
    }
    const std::string sec_sign = obn::signing::device_security_sign();
    OBN_DEBUG("cloud_print: create_task app_cert_id='%s' (len=%zu) sec_sign_len=%zu",
              app_id.c_str(), app_id.size(), sec_sign.size());
    ohdrs.emplace_back("x-bbl-app-certification-id", app_id);
    ohdrs.emplace_back("x-bbl-device-security-sign", sec_sign);
    req.ordered_headers = std::move(ohdrs);
    req.body      = body;
    req.timeout_s = 60;

    auto resp = obn::http::perform(req);

    // Hard-fail on any transport error or non-2xx: POST /my/task registers the
    // print with MakerWorld and, for cloud prints, is what actually authorizes
    // the printer to fetch the uploaded content. Swallowing its failure led to
    // silent breakage (the job would proceed with task_id=0 and then stall on
    // the printer with "failed to download"), so surface it instead.
    // The most common cause of a 403 here is X-BBL-Client-Name != "BambuStudio"
    // (see config::client_name) or an X-BBL-OS-Type / uploader-OS mismatch.
    // Note: this path is only reached for cloud prints (bambu_network_start_print)
    // and "local print with record" (start_local_print_with_record); block_cloud
    // stops run_cloud_print_job before we ever get here, and pure LAN printing
    // (start_local_print -> run_local_print_job) never calls /my/task.
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300)
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_POST_TASK_FAILED,
                          "create_task", resp);

    auto root = obn::json::parse(resp.body);
    if (!root) {
        OBN_WARN("cloud_print: create_task bad JSON; continuing with task_id=0");
        *out_task_id = "0";
        return 0;
    }
    *out_task_id = root->find("id").as_string();
    if (out_task_id->empty()) {
        // Some builds return id as an integer; json_lite as_string()
        // returns empty for numeric values.
        const auto& rbody = resp.body;
        auto pos = rbody.find("\"id\"");
        if (pos != std::string::npos) {
            pos = rbody.find_first_of("0123456789", pos);
            if (pos != std::string::npos) {
                auto end = rbody.find_first_not_of("0123456789", pos);
                *out_task_id = rbody.substr(pos, end == std::string::npos
                                                 ? std::string::npos
                                                 : end - pos);
            }
        }
    }
    if (out_task_id->empty()) {
        OBN_WARN("cloud_print: create_task missing task_id; continuing with task_id=0");
        *out_task_id = "0";
    }
    OBN_INFO("cloud_print: task_id=%s", out_task_id->c_str());
    return 0;
}

} // namespace

#ifdef OBN_TESTING
// Thin wrappers that give anonymous-namespace functions external linkage
// so cloud_print_test can exercise them without extracting them.
namespace cloud_print {
std::string test_ams_mapping2(const BBL::PrintParams& p)
    { return ams_mapping2_for_cloud(p); }
std::string test_build_task_body(const BBL::PrintParams& p,
                                 const std::string& project_id,
                                 const std::string& model_id,
                                 const std::string& profile_id,
                                 bool use_lan_channel)
    { return build_task_body(p, project_id, model_id, profile_id, use_lan_channel); }
} // namespace cloud_print
#endif

int Agent::run_cloud_print_job(const BBL::PrintParams& p,
                               BBL::OnUpdateStatusFn   update_fn,
                               BBL::WasCancelledFn     cancel_fn,
                               bool                    use_lan_channel)
{
    use_lan_channel = true;
    OBN_INFO("cloud_print dev=%s ip=%s plate=%d file=%s config=%s project=%s chan=%s",
             p.dev_id.c_str(), p.dev_ip.c_str(), p.plate_index,
             p.filename.c_str(), p.config_filename.c_str(),
             p.project_name.c_str(),
             use_lan_channel ? "lan" : "cloud");

    // Studio's PrintJob::process picks the ABI entry point:
    //   start_local_print_with_record -> use_lan_channel=true
    //   start_print                   -> use_lan_channel=false
    //
    // LAN ("record") path: upload 3mf to the printer over LAN, POST /my/task
    // with mode=lan_file as a cloud history record only (cloud does NOT
    // dispatch lan_file to the printer), then trigger print with a plaintext
    // LAN MQTT project_file. Cloud-bound printers never get a LanSession from
    // Studio's connect_printer, so we open it ourselves via ensure_lan_session.

    if (p.filename.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "empty filename");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }

    // Ensure the :6000 upload leg (brtc/emmc) can verify the printer's
    // self-signed leaf: publish the LAN-TLS peer pin from the on-disk cert
    // even when no LAN connect_printer ran this session (cloud-only usage).
    publish_peer_cert_pin(p.dev_ip, p.dev_id);

    // Hard stop: never push a print file through Bambu's cloud when the
    // user has opted out. Studio normally avoids this path because the
    // printer is never marked cloud-online under block_cloud, but a future
    // Studio update or unexpected dispatch must not be able to upload to
    // S3 behind the user's back. See issue #41.
    if (obn::config::current().block_cloud) {
        OBN_WARN("run_cloud_print_job: blocked by block_cloud");
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "cloud print blocked by config");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    auto session = user_session_snapshot();
    if (session.access_token.empty() || session.user_id.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "not logged in");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    const std::string api   = obn::cloud::api_host(cloud_region());
    const std::string token = session.access_token;
    const std::string uid   = session.user_id;

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");
    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

    // -------------------------------------------------------------
    // [A] Create the cloud project and get the first presigned URL
    // -------------------------------------------------------------
    std::string project_name = p.project_name.empty() ? p.task_name : p.project_name;
    if (project_name.empty()) project_name = "untitled";
    ProjectInfo info{};
    if (int rc = create_project(api, token, uid, project_name, &info, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [B] Upload the config 3mf (small). Studio generates it next to
    // the main 3mf; if it's missing we fall back to the main file so
    // we at least have *something* for the archive.
    // -------------------------------------------------------------
    std::string config_path = p.config_filename.empty() ? p.filename : p.config_filename;
    std::string slurp_err;
    std::string config_bytes = slurp_file(config_path, &slurp_err);
    if (config_bytes.empty()) {
        OBN_ERROR("cloud_print: config read %s: %s",
                  config_path.c_str(), slurp_err.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "config_filename not readable");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    // Upload progress for the config file is tiny and confusing in the
    // UI; we report 0% at start and 10% after. The big file (step G)
    // owns 10..95%.
    // TODO: test progress reporting
    if (int rc = s3_put(info.upload_url, config_bytes, update_fn, cancel_fn,
                        /*stage_start_pct=*/0, /*stage_end_pct=*/10,
                        BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_3MF_CONFIG_TO_OSS_FAILED);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [C/D] Notify + poll.
    // -------------------------------------------------------------
    std::string origin_cfg = std::filesystem::path(config_path).filename().string();
    if (int rc = notify_upload(api, token, uid, info.upload_ticket,
                               origin_cfg, update_fn);
        rc != 0) return rc;
    if (int rc = poll_upload(api, token, uid, info.upload_ticket,
                             update_fn, cancel_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [E] First PATCH - placeholder ftp:// url. Studio always does
    // this before uploading the real 3mf.
    // -------------------------------------------------------------
    std::string remote_name = print_job::pick_remote_name(p);
    std::string ftp_url     = "ftp://" + remote_name;
    std::string md5         = p.ftp_file_md5;
    // The printer will re-compute md5 on download; if Studio didn't
    // give us one, keep the field so the server schema stays happy.
    if (md5.empty()) md5 = "00000000000000000000000000000000"; // TODO: ensure that it is a valid md5

    if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                               md5, p.plate_index, ftp_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [F] Get the second presigned URL (for the main 3mf).
    // Studio composes model_slot = "<model_id>_<profile_id>_<plate>.3mf".
    // -------------------------------------------------------------
    std::string plate_tag = std::to_string(p.plate_index <= 0 ? 1 : p.plate_index);
    std::string model_slot = info.model_id + "_" + info.profile_id + "_" + plate_tag + ".3mf";
    std::string main_upload_url;
    if (int rc = get_upload_url(api, token, uid, model_slot, &main_upload_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [G] Upload the print-ready 3mf (big).
    // -------------------------------------------------------------
    std::string main_bytes = slurp_file(p.filename, &slurp_err);
    if (main_bytes.empty()) {
        OBN_ERROR("cloud_print: main read %s: %s", p.filename.c_str(), slurp_err.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "filename not readable");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    if (int rc = s3_put(main_upload_url, main_bytes, update_fn, cancel_fn,
                        /*stage_start_pct=*/10, /*stage_end_pct=*/95,
                        BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_3MF_TO_OSS_FAILED);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [H] Second PATCH with the real URL.
    // -------------------------------------------------------------
    if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                               md5, p.plate_index, main_upload_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [9/I] LAN-only: upload to printer storage, then POST task with
    // mode=lan_file. Cloud variant skips local upload.
    // -------------------------------------------------------------
    std::string lan_remote_path; // wire path / basename for MQTT
    if (use_lan_channel) {
        // Studio asked for the LAN channel
        if (p.dev_ip.empty() || p.password.empty()) {
            OBN_ERROR("cloud_print: lan channel requested but no dev_ip/access_code");
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                     "no dev_ip/access_code for LAN print");
            return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
        }
        if (!ensure_lan_session(p.dev_id, p.dev_ip, p.password)) {
            OBN_ERROR("cloud_print: no LAN MQTT session for dev=%s",
                      p.dev_id.c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                     "LAN MQTT session failed");
            return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
        }
        if (print_job::use_brtc_cache_upload(p)) {
            OBN_INFO("cloud_print: upload path=brtc :6000 (try_emmc_print=%d, force_ftps=%d)",
                     p.try_emmc_print ? 1 : 0,
                     obn::config::current().force_ftps ? 1 : 0);
            obn::tunnel_upload::ConnectParams cp =
                obn::tunnel_upload::connect_params_from_print(
                    p.dev_ip, p.dev_id, p.password);
            obn::tunnel_upload::UploadRequest ureq;
            ureq.local_path   = p.filename;
            ureq.dest_storage = "emmc";
            ureq.dest_name    = remote_name;

            obn::tunnel_upload::UploadCallbacks cb;
            cb.cancelled = [&]() { return cancel_fn && cancel_fn(); };
            cb.progress = [&](int pct) {
                if (update_fn) update_fn(BBL::PrintingStageUpload, pct, "");
            };

            obn::tunnel_upload::UploadOutcome outcome;
            if (int rc = obn::tunnel_upload::upload_file(
                    cp, ureq, cb, &outcome,
                    BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED);
                rc != 0) return rc;
            lan_remote_path = remote_name;
            OBN_INFO("cloud_print: brtc upload %llu bytes to emmc/%s",
                     static_cast<unsigned long long>(outcome.bytes),
                     remote_name.c_str());
        } else {
            OBN_INFO("cloud_print: upload path=ftps :990 (try_emmc_print=%d, force_ftps=%d)",
                     p.try_emmc_print ? 1 : 0,
                     obn::config::current().force_ftps ? 1 : 0);
            std::string folder = p.ftp_folder;
            if (!folder.empty() && folder.back() != '/') folder += '/';
            if (!folder.empty() && folder.front() == '/') folder.erase(0, 1);
            lan_remote_path = "/" + folder + remote_name;

            print_params_set_use_ssl_for_ftp(p.use_ssl_for_ftp);

            std::uint64_t total = 0;
            std::string ca_file = bambu_ca_bundle_path();
            std::string stored_path;
            if (int rc = print_job::ftp_upload(p, lan_remote_path, ca_file,
                                               update_fn, cancel_fn,
                                               BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                               total, &stored_path);
                rc != 0) return rc;
            if (!stored_path.empty()) lan_remote_path = stored_path;
            OBN_INFO("cloud_print: lan-ftps uploaded %llu bytes to %s",
                     static_cast<unsigned long long>(total), lan_remote_path.c_str());
        }
    }

    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    // oriModelId/oriProfileId name the source design a model was derived from.
    // BambuStudio fills these from the 3mf before calling us, but a standalone
    // caller may leave them empty, so recover them from the 3mf's DesignModelId
    // metadata. A locally-authored model has no source design -> empty oriModelId,
    // which the cloud accepts (see build_task_body's contract note).
    BBL::PrintParams tp = p;
    if (tp.origin_model_id.empty() && !tp.filename.empty()) {
        std::string design_model_id;
        int design_profile_id = 0;
        if (print_job::read_3mf_design_ids(tp.filename, &design_model_id, &design_profile_id)) {
            tp.origin_model_id   = design_model_id;
            tp.origin_profile_id = design_profile_id;
            OBN_INFO("cloud_print: recovered oriModelId=%s oriProfileId=%d from 3mf",
                     design_model_id.c_str(), design_profile_id);
        }
    }
    std::string task_body = build_task_body(tp, info.project_id, info.model_id,
                                            info.profile_id, use_lan_channel);
    std::string task_id;
    if (int rc = create_task(api, token, uid, task_body, &task_id, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [J] MQTT publish the project_file command. The printer watches
    // for this on its report/request channel and starts the job the
    // moment it lands.
    // -------------------------------------------------------------
    print_job::ProjectFileOpts opts;
    opts.project_id = info.project_id;
    opts.profile_id = info.profile_id;
    opts.task_id    = task_id;
    opts.subtask_id = "0";
    opts.md5        = md5;
    if (use_lan_channel) {
        opts.file_path = lan_remote_path;
        if (print_job::use_brtc_cache_upload(p)) {
            opts.url = print_job::build_brtc_emmc_url(remote_name);
        } else {
            opts.url = print_job::build_ftp_url(lan_remote_path);
        }
    } else {
        // Cloud: the printer fetches directly from S3 over HTTPS.
        opts.file_path = remote_name;
        opts.url       = main_upload_url;
    }
    OBN_INFO("cloud_print: project_file chan=%s file=%s url=%s",
             use_lan_channel ? "lan" : "cloud",
             opts.file_path.c_str(), redact_url(opts.url).c_str());

    // Plaintext project_file JSON. send_message prefers LAN MQTT when a
    // session is up; cloud MQTT is only the fallback. REST already recorded
    // the job for MakerWorld Ã¢â‚¬â€ no need to force cloud for the trigger.
    // const std::string mqtt_json = print_job::build_project_file_json(p, opts);
    // OBN_DEBUG("cloud_print mqtt: %s", mqtt_json.c_str());

    // int pub_rc = send_message(p.dev_id, mqtt_json, /*qos=*/0);
    // if (pub_rc != 0) {
    //     OBN_ERROR("cloud_print: mqtt publish failed rc=%d", pub_rc);
    //     if (update_fn) update_fn(BBL::PrintingStageERROR,
    //                              BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED,
    //                              "MQTT publish failed");
    //     return BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED;
    // }

    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("cloud_print dev=%s: queued (project=%s task=%s upload=%s)",
             p.dev_id.c_str(), info.project_id.c_str(), task_id.c_str(),
             use_lan_channel ? "lan" : "cloud");
    return 0;
}

// Uppercase-hex MD5 of a local file. The O1S/H2S firmware cross-checks the
// uploaded 3mf against print.md5 and refuses the job with 0500-4003 ("unable to
// parse the file") on an empty OR mismatched hash - which is exactly what an
// empty md5 field produced on the first hybrid attempt. Mirrors print_job.cpp's
// md5_of_file (file-local there, so duplicated here rather than exported).
static std::string hybrid_md5_hex_of_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    EVP_MD_CTX* ctx = ::EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string hex;
    if (::EVP_DigestInit_ex(ctx, ::EVP_md5(), nullptr) == 1) {
        std::vector<char> buf(64 * 1024);
        bool ok = true;
        while (f.read(buf.data(), static_cast<std::streamsize>(buf.size())) ||
               f.gcount() > 0) {
            if (::EVP_DigestUpdate(ctx, buf.data(),
                                   static_cast<size_t>(f.gcount())) != 1) {
                ok = false;
                break;
            }
        }
        if (ok) {
            unsigned char digest[EVP_MAX_MD_SIZE] = {0};
            unsigned      len = 0;
            if (::EVP_DigestFinal_ex(ctx, digest, &len) == 1) {
                static const char kHex[] = "0123456789ABCDEF";
                hex.resize(len * 2);
                for (unsigned i = 0; i < len; ++i) {
                    hex[2 * i]     = kHex[(digest[i] >> 4) & 0xF];
                    hex[2 * i + 1] = kHex[ digest[i]       & 0xF];
                }
            }
        }
    }
    ::EVP_MD_CTX_free(ctx);
    return hex;
}

// ---------------------------------------------------------------------------
// Path A (hybrid). Stage the full .gcode.3mf on the printer over LAN FTPS, then
// publish the project_file command - url_enc/param_enc'd to the printer's own
// TLS-leaf cert - over the CLOUD MQTT broker instead of the LAN broker.
//
// Rationale: the O1S / H2S firmware cancels a LAN-broker project_file with
// fail_reason 50348044 ("task canceled") even when it is correctly signed and
// the referenced file is already present, but it honours the identical command
// when it arrives over the cloud channel. No create_task / S3 upload is
// involved, so this needs only a live cloud MQTT session (username=u_<uid>,
// password=token) - not the RSA app-cert that create_task's
// x-bbl-device-security-sign requires (that path 403s).
// ---------------------------------------------------------------------------
int Agent::run_hybrid_print_job(const BBL::PrintParams& p,
                                BBL::OnUpdateStatusFn   update_fn,
                                BBL::WasCancelledFn     cancel_fn)
{
    OBN_INFO("hybrid_print dev=%s ip=%s plate=%d file=%s",
             p.dev_id.c_str(), p.dev_ip.c_str(), p.plate_index, p.filename.c_str());

    if (p.filename.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST, "empty filename");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    if (p.dev_ip.empty() || p.password.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                 "hybrid print needs dev_ip + access_code for the LAN upload");
        return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
    }

    // The command goes over the cloud broker, so a cloud session is mandatory.
    auto session = user_session_snapshot();
    if (session.access_token.empty() || session.user_id.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "hybrid print needs a cloud login (token)");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    if (obn::config::current().block_cloud) {
        OBN_WARN("run_hybrid_print_job: cloud publish blocked by block_cloud");
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "hybrid print blocked by block_cloud=1");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");
    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

    // Normalise the exported plate to plate_1 (rename Metadata/plate_<N>.gcode
    // -> plate_1.gcode, shift model_settings + plate assets, drop stray
    // lower-plate thumbnails). Studio exports the SELECTED plate as plate_<N>,
    // but the O1S/H2S firmware refuses to parse a spool whose gcode entry isn't
    // plate_1 - that is the 0500-4003 "unable to parse the file" we hit with a
    // plate_2 spool. Mirrors run_send_gcode_to_sdcard + the proven LAN recipe.
    // Must run BEFORE the FTPS upload and the md5 hash below (it rewrites the
    // file in place), so both see the normalised plate_1 archive.
    if (!p.filename.empty() && !print_job::normalise_to_plate_one(p.filename)) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                 "plate normalisation failed");
        return BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED;
    }

    // --- 1. Stage the .gcode.3mf on the printer via LAN FTPS -----------------
    std::string remote_name = print_job::pick_remote_name(p);
    std::string folder = p.ftp_folder;
    if (!folder.empty() && folder.back()  != '/') folder += '/';
    if (!folder.empty() && folder.front() == '/') folder.erase(0, 1);
    std::string lan_remote_path = "/" + folder + remote_name;

    print_params_set_use_ssl_for_ftp(p.use_ssl_for_ftp);

    std::uint64_t total = 0;
    std::string ca_file = bambu_ca_bundle_path();
    std::string stored_path;
    if (update_fn) update_fn(BBL::PrintingStageUpload, 0, "");
    if (int rc = print_job::ftp_upload(p, lan_remote_path, ca_file,
                                       update_fn, cancel_fn,
                                       BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                       total, &stored_path);
        rc != 0) return rc;
    if (!stored_path.empty()) lan_remote_path = stored_path;
    OBN_INFO("hybrid_print: lan-ftps uploaded %llu bytes to %s",
             static_cast<unsigned long long>(total), lan_remote_path.c_str());

    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;
    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    // --- 2. RSA-encrypt url + param to the printer's captured leaf cert ------
    std::string url         = print_job::build_ftp_url(lan_remote_path);
    std::string pem_path    = cert_store::device_cert_path(config_dir(), p.dev_id);
    // After normalise_to_plate_one the gcode entry is always plate_1.gcode.
    std::string plate_param = "Metadata/plate_1.gcode";

    std::string enc_err;
    std::string url_enc   = rsa_pkcs1v15_encrypt_b64(pem_path, url,         &enc_err);
    std::string param_enc = rsa_pkcs1v15_encrypt_b64(pem_path, plate_param, &enc_err);
    if (url_enc.empty() || param_enc.empty()) {
        OBN_ERROR("hybrid_print: RSA field encryption failed (%s); cert=%s dev=%s",
                  enc_err.c_str(), pem_path.c_str(), p.dev_id.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                 "RSA field encryption failed: " + enc_err);
        return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
    }

    // --- 3. Build the project_file payload (no cloud project / task ids) -----
    print_job::CloudProjectFileOpts cloud_opts;
    cloud_opts.url_enc    = std::move(url_enc);
    cloud_opts.param_enc  = std::move(param_enc);
    cloud_opts.file_path  = lan_remote_path;
    cloud_opts.md5        = p.ftp_file_md5;
    if (cloud_opts.md5.empty()) {
        // Studio leaves ftp_file_md5 empty; hash the uploaded file ourselves so
        // the firmware's print.md5 cross-check passes. An empty md5 makes the
        // O1S/H2S refuse the job with 0500-4003 ("unable to parse the file").
        cloud_opts.md5 = hybrid_md5_hex_of_file(p.filename);
        if (cloud_opts.md5.empty())
            OBN_WARN("hybrid_print: failed to MD5 %s; sending empty md5 "
                     "(firmware will likely refuse the job)", p.filename.c_str());
    }
    cloud_opts.project_id = "0";
    cloud_opts.profile_id = "0";
    cloud_opts.task_id    = "0";
    cloud_opts.subtask_id = "0";
    std::string mqtt_json = print_job::build_cloud_project_file_json(p, cloud_opts);
    OBN_DEBUG("hybrid_print mqtt(cloud): %s", mqtt_json.c_str());

    // --- 4. Publish the signed project_file over the CLOUD broker. This is the
    //        crux of Path A: the file lives on the printer (staged over LAN
    //        FTPS) but the command arrives over the cloud channel, which the
    //        O1S/H2S accepts where it rejects a LAN-broker command. A normal
    //        LAN-broker print is run_local_print_job's job, not this one.
    //        cloud_send_message applies maybe_sign (the enc_msg envelope) first.
    int pub_rc = cloud_send_message(p.dev_id, mqtt_json, /*qos=*/0);
    if (pub_rc != 0) {
        OBN_ERROR("hybrid_print: cloud mqtt publish failed rc=%d "
                  "(is the cloud session connected?)", pub_rc);
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED,
                                 "cloud MQTT publish failed");
        return BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED;
    }

    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("hybrid_print dev=%s: project_file published over cloud (normalised plate_1)",
             p.dev_id.c_str());
    return 0;
}

} // namespace obn
