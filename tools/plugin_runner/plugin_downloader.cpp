#include "plugin_downloader.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <curl/curl.h>
#include <minizip/unzip.h>
#include <nlohmann/json.hpp>

// Implements the plugin discovery + download flow Bambu Studio itself
// uses (PresetUpdater::priv::sync_plugins, src/slic3r/Utils/PresetUpdater.cpp:1165).
//
// 1. GET https://api.bambulab.com/v1/iot-service/api/slicer/resource
//        ?slicer/plugins/cloud=<MM.mm.pp>.00
//    Response: { "message": "success", "resources": [
//                  { "type": "slicer/plugins/cloud", "version": "01.10.04.00",
//                    "url": "https://files.bambulab.com/.../plugins.zip",
//                    "force_update": false, "description": "" } ]}
// 2. Cache lookup: <cache_dir>/<version>/libbambu_networking.so. If
//    present and `force` is false, short-circuit.
// 3. Otherwise GET the `url` into a temp file, then unzip. The .so lives
//    inside the archive at one of a couple of paths that have varied
//    across releases (e.g. `linux/libbambu_networking.so`, plain
//    `libbambu_networking.so`, sometimes nested under a versioned dir).
//    We just walk the archive and pick the first entry whose basename
//    is `libbambu_networking.so`.

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace obn::plugin_runner {

namespace {

constexpr const char* kApiBase = "https://api.bambulab.com/v1/iot-service/api/slicer/resource";
constexpr const char* kResourceType = "slicer/plugins/cloud";
constexpr const char* kSoBasename   = "libbambu_networking.so";

bool valid_abi_prefix(const std::string& s)
{
    static const std::regex re("^[0-9]{2}\\.[0-9]{2}\\.[0-9]{2}$");
    return std::regex_match(s, re);
}

size_t curl_write_string(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::string*>(userdata);
    out->append(static_cast<const char*>(ptr), size * nmemb);
    return size * nmemb;
}

size_t curl_write_file(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* f = static_cast<std::FILE*>(userdata);
    return std::fwrite(ptr, size, nmemb, f);
}

struct HttpResult {
    bool        ok = false;
    long        status = 0;
    std::string body;
    std::string error;
};

// Bambu's `/slicer/resource` endpoint switches the returned `url` based on
// X-BBL-OS-Type (e.g. "linux" -> linux_*.zip, "windows" -> win_*.zip,
// macos -> mac_*.zip). Without the header it defaults to Windows, so
// every request from this tool needs the linux marker.
struct curl_slist* studio_headers()
{
    struct curl_slist* h = nullptr;
    h = curl_slist_append(h, "X-BBL-Client-Type: slicer");
    h = curl_slist_append(h, "X-BBL-Client-Name: OpenBambooNetworking");
    h = curl_slist_append(h, "X-BBL-OS-Type: linux");
    return h;
}

HttpResult http_get_string(const std::string& url, long timeout_s = 30)
{
    HttpResult r;
    CURL* h = curl_easy_init();
    if (!h) {
        r.error = "curl_easy_init failed";
        return r;
    }
    struct curl_slist* hdrs = studio_headers();
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, curl_write_string);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "obn-plugin-runner/1");
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);

    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode code = curl_easy_perform(h);
    if (code == CURLE_OK) {
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &r.status);
        r.ok = (r.status >= 200 && r.status < 300);
        if (!r.ok) r.error = "HTTP " + std::to_string(r.status);
    } else {
        r.error = errbuf[0] ? errbuf : curl_easy_strerror(code);
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    return r;
}

HttpResult http_get_file(const std::string& url, const std::string& dst_path,
                         long timeout_s = 120)
{
    HttpResult r;
    std::FILE* f = std::fopen(dst_path.c_str(), "wb");
    if (!f) {
        r.error = "cannot open " + dst_path + ": " + std::strerror(errno);
        return r;
    }
    CURL* h = curl_easy_init();
    if (!h) {
        std::fclose(f);
        r.error = "curl_easy_init failed";
        return r;
    }
    struct curl_slist* hdrs = studio_headers();
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, curl_write_file);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, f);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "obn-plugin-runner/1");
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);

    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode code = curl_easy_perform(h);
    if (code == CURLE_OK) {
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &r.status);
        r.ok = (r.status >= 200 && r.status < 300);
        if (!r.ok) r.error = "HTTP " + std::to_string(r.status);
    } else {
        r.error = errbuf[0] ? errbuf : curl_easy_strerror(code);
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    std::fclose(f);
    return r;
}

// Walks `zip_path` and writes the first entry whose basename equals
// `wanted_basename` to `dst_path`. Returns true on success. Doesn't try
// to be clever about case sensitivity, symlinks, or zip64 — the Bambu
// archives are well-formed and small.
bool unzip_extract_basename(const std::string& zip_path,
                            const std::string& wanted_basename,
                            const std::string& dst_path,
                            std::string&       err)
{
    unzFile uf = unzOpen(zip_path.c_str());
    if (!uf) {
        err = "unzOpen failed for " + zip_path;
        return false;
    }
    if (unzGoToFirstFile(uf) != UNZ_OK) {
        err = "unzGoToFirstFile failed";
        unzClose(uf);
        return false;
    }
    bool found = false;
    do {
        char fname[1024] = {0};
        unz_file_info info{};
        if (unzGetCurrentFileInfo(uf, &info, fname, sizeof(fname),
                                  nullptr, 0, nullptr, 0) != UNZ_OK) continue;
        std::string entry(fname);
        std::string base = entry;
        auto slash = base.rfind('/');
        if (slash != std::string::npos) base = base.substr(slash + 1);
        if (base != wanted_basename) continue;

        if (unzOpenCurrentFile(uf) != UNZ_OK) {
            err = "unzOpenCurrentFile failed for " + entry;
            break;
        }
        std::FILE* f = std::fopen(dst_path.c_str(), "wb");
        if (!f) {
            err = std::string("cannot open ") + dst_path + ": " + std::strerror(errno);
            unzCloseCurrentFile(uf);
            break;
        }
        std::vector<char> buf(64 * 1024);
        int n;
        while ((n = unzReadCurrentFile(uf, buf.data(),
                static_cast<unsigned int>(buf.size()))) > 0) {
            if (std::fwrite(buf.data(), 1, static_cast<size_t>(n), f) != static_cast<size_t>(n)) {
                err = "short write to " + dst_path;
                std::fclose(f);
                unzCloseCurrentFile(uf);
                unzClose(uf);
                return false;
            }
        }
        std::fclose(f);
        unzCloseCurrentFile(uf);
        if (n < 0) {
            err = "unzReadCurrentFile failed for " + entry +
                  " (code " + std::to_string(n) + ")";
            break;
        }
        // Make sure the extracted .so is executable by dlopen-time loaders.
        ::chmod(dst_path.c_str(), 0755);
        found = true;
        break;
    } while (unzGoToNextFile(uf) == UNZ_OK);
    unzClose(uf);
    if (!found && err.empty()) {
        err = "no entry named '" + wanted_basename + "' inside " + zip_path;
    }
    return found;
}

} // namespace

DownloadResult fetch_plugin(const std::string& abi_prefix,
                            const std::string& cache_dir,
                            bool               force)
{
    DownloadResult out;

    if (!valid_abi_prefix(abi_prefix)) {
        out.error_message = "bad abi prefix '" + abi_prefix +
            "', expected MM.mm.pp (e.g. 02.05.03)";
        return out;
    }

    // Studio sends the version inside the query as `MM.mm.pp.00`. The
    // suffix is required by the API even though we don't use the
    // patch-level component.
    std::string using_version = abi_prefix + ".00";
    std::string url = std::string(kApiBase) + "?" + kResourceType + "=" + using_version;

    HttpResult q = http_get_string(url, 20);
    out.http_status = static_cast<int>(q.status);
    if (!q.ok) {
        out.error_message = "metadata GET failed: " + q.error;
        return out;
    }
    json meta;
    try {
        meta = json::parse(q.body);
    } catch (const std::exception& e) {
        out.error_message = std::string("metadata parse failed: ") + e.what();
        return out;
    }
    if (!meta.contains("message") || meta["message"].get<std::string>() != "success") {
        out.error_message = "API rejected the query: " + q.body;
        return out;
    }
    if (!meta.contains("resources") || !meta["resources"].is_array() ||
        meta["resources"].empty()) {
        out.error_message = "API returned no resources for " + using_version;
        return out;
    }
    std::string archive_url, version;
    for (const auto& r : meta["resources"]) {
        if (!r.contains("type") || r["type"].get<std::string>() != kResourceType) continue;
        if (r.contains("version")) version     = r["version"].get<std::string>();
        if (r.contains("url"))     archive_url = r["url"].get<std::string>();
        break;
    }
    if (archive_url.empty() || version.empty()) {
        out.error_message = "API response missing url/version: " + q.body;
        return out;
    }
    out.version = version;

    // Cache layout: <cache_dir>/<version>/libbambu_networking.so
    fs::path target_dir = fs::path(cache_dir) / version;
    fs::path target_so  = target_dir / kSoBasename;
    std::error_code ec;
    fs::create_directories(target_dir, ec);
    if (ec) {
        out.error_message = "cannot create " + target_dir.string() + ": " + ec.message();
        return out;
    }
    if (!force && fs::exists(target_so, ec)) {
        out.ok = true;
        out.so_path = target_so.string();
        return out;
    }

    fs::path tmp_zip = target_dir / "plugin.zip.partial";
    HttpResult dl = http_get_file(archive_url, tmp_zip.string(), 180);
    out.http_status = static_cast<int>(dl.status);
    if (!dl.ok) {
        out.error_message = "archive GET failed (" + archive_url + "): " + dl.error;
        fs::remove(tmp_zip, ec);
        return out;
    }

    std::string err;
    if (!unzip_extract_basename(tmp_zip.string(), kSoBasename, target_so.string(), err)) {
        out.error_message = "unzip failed: " + err;
        fs::remove(tmp_zip, ec);
        return out;
    }
    fs::remove(tmp_zip, ec);

    out.ok = true;
    out.so_path = target_so.string();
    return out;
}

} // namespace obn::plugin_runner
