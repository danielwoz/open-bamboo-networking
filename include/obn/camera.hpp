#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace obn::camera {

// Printer models that support native JPEG streaming on port 6000.
bool is_jpeg_model(const std::string& model);

struct JpegConfig {
    std::string dev_id;
    std::string ip;
    std::string access_code;
    int port                = 6000;
    int connect_timeout_ms  = 5000;
    int read_timeout_ms     = 10000;
};

// Starts a JPEG camera session for the given printer.
// Returns the local URL to give to Studio (http://127.0.0.1:PORT/cam),
// or empty string on failure.
std::string start_camera(const JpegConfig& cfg);

// Stops the camera session for this dev_id.
void stop_camera(const std::string& dev_id);

// Returns the current stream URL for dev_id, or empty if not active.
std::string get_url(const std::string& dev_id);

} // namespace obn::camera
