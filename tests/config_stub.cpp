// Minimal stubs for obn::config — returns mutable Settings so that
// signing_test can inject key/cert paths without the full config chain.

#include "obn/config.hpp"

#include <filesystem>

namespace obn::config {

static Settings  g_test_settings;
static std::string g_test_dir;

Settings& test_settings() { return g_test_settings; }
std::string& test_dir()   { return g_test_dir; }

const Settings& current() { return g_test_settings; }
const std::string& dir()  { return g_test_dir; }

std::string path_in_dir(const std::string& basename)
{
    if (g_test_dir.empty()) return {};
    return (std::filesystem::path(g_test_dir) / basename).string();
}

std::string cloud_api_host_for(const Settings&, const std::string&)
{
    return "https://api.bambulab.com";
}

std::string cloud_web_host_for(const Settings&, const std::string&)
{
    return "https://bambulab.com";
}

} // namespace obn::config
