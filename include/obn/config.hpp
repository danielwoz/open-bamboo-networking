#pragma once

// User-editable settings in <config_dir>/obn.conf (INI-like key = value).
// Loaded once from bambu_network_create_agent(log_dir). Environment
// variables override individual keys where documented (see log.hpp).

#include <string>

namespace obn::config {

inline constexpr const char* kConfigFileName = "obn.conf";

struct Settings {
    // Logging (empty string = use built-in default for that key)
    std::string log_level;
    std::string log_stderr;
    std::string log_to_file;
    std::string log_file;

    // Cloud endpoints (per region; empty value falls back to production default)
    std::string cloud_global_api_host;
    std::string cloud_global_web_host;
    std::string cloud_global_mqtt_host;
    std::string cloud_cn_api_host;
    std::string cloud_cn_web_host;
    std::string cloud_cn_mqtt_host;

    // LAN / cloud networking
    bool lan_tls_skip_verify      = false;
    int  cloud_mqtt_port          = 8883;
    bool block_cloud              = true;

    // Print behavior overrides
    bool force_timelapse_external = false;

    // Route "Send print" through the cloud path (run_cloud_print_job) instead
    // of the plaintext LAN project_file. Newer firmware (H2/O-series, e.g. O1S)
    // rejects a plaintext LAN project_file with fail_reason 50348044 ("task
    // canceled"): it prepares the file then cancels because the print was not
    // authorized/encrypted the way the cloud path does (RSA param_enc/url_enc).
    // Mirrors what Bambu Studio does for these printers. Requires block_cloud=0
    // and a logged-in Bambu account.
    bool force_cloud_print           = false;
    // When force_cloud_print is on, choose the channel for the project_file:
    //   false (default) = cloud channel: full S3 upload + command published via
    //                     the cloud MQTT broker (matches Studio's observed path).
    //   true            = LAN channel: upload to the printer over LAN + command
    //                     published to the printer's local MQTT, still RSA
    //                     param_enc/url_enc encrypted, plus a cloud task record.
    // Lets us test both without a rebuild if one channel misbehaves.
    bool force_cloud_print_lan_channel = false;

    // Path A (hybrid) for O1S/H2S: upload the .gcode.3mf to the printer over
    // LAN FTPS, but publish the url_enc/param_enc project_file command over the
    // CLOUD MQTT broker (run_hybrid_print_job). Sidesteps both the LAN-broker
    // 50348044 cancel and the cloud create_task RSA app-cert 403. Requires
    // block_cloud=0 and a logged-in Bambu account. Takes precedence over
    // force_cloud_print when both are set.
    bool force_hybrid_print          = false;

    // File transfer
    bool force_ftps               = false;

    // Device panel: static "Printer Preview" JPEG (mem:/N over TLS :6000)
    bool disable_camera_preview      = false;

    // MQTT connection persistence: Orca Slicer unconditionally tears down
    // and re-establishes the MQTT session after every print job, causing a
    // 5-30s reconnection delay.  Enabled by default to work around this.
    bool mqtt_keep_connection        = true;

    // Replace the LAN IP reported by the printer in push_status with the
    // IP used in connect_printer.  Needed for NAT / port-forwarding setups
    // where the printer advertises its internal LAN address but the slicer
    // must reach it via a different (public) IP.
    bool override_lan_ip             = false;

    // MQTT push_status patches (all off by default)
    bool patch_mqtt_home_flag        = false;
    bool patch_mqtt_ipcam_file       = false;
    bool patch_mqtt_internal_storage = false;

    // BambuSource logging — propagated to libBambuSource via obn.env
    std::string bambusource_log_level;
    std::string bambusource_log_stderr;
    std::string bambusource_log_to_file;
    std::string bambusource_log_file;
};

// Parse "0"/"1"/"true"/"false"/"yes"/"no" (case-insensitive) into a bool.
// Returns `fallback` for unrecognised values.
bool truthy(const std::string& val, bool fallback = false);

// Load from <config_dir>/obn.conf; create a commented template if missing.
// Thread-safe; subsequent calls return the same cached Settings until
// load_or_create is called with a different non-empty directory.
Settings load_or_create(const std::string& config_dir);

// Parse an existing obn.conf without creating a template if absent.
// Returns default Settings when the file does not exist.
Settings load_if_exists(const std::string& config_dir);

// Valid only after load_or_create(); otherwise returns default Settings.
const Settings& current();

// Resolve cloud endpoints for `region` ("CN"/"cn" = China, else global).
// Empty configured values fall back to production defaults.
std::string cloud_api_host_for(const Settings& s, const std::string& region);
std::string cloud_web_host_for(const Settings& s, const std::string& region);
std::string cloud_mqtt_host_for(const Settings& s, const std::string& region);

} // namespace obn::config
