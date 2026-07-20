#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"

using obn::as_agent;

namespace {
void log_print_params(const char* which, const BBL::PrintParams& p)
{
    OBN_INFO("%s dev=%s ip=%s ssl_mqtt=%d ssl_ftp=%d task=%s plate=%d ams=%s 3mf=%s md5=%s",
             which, p.dev_id.c_str(), p.dev_ip.c_str(), p.use_ssl_for_mqtt, p.use_ssl_for_ftp,
             p.task_name.c_str(), p.plate_index,
             p.ams_mapping.c_str(),
             p.ftp_file.c_str(), p.ftp_file_md5.c_str());
}
} // namespace

OBN_ABI int bambu_network_start_print(void* agent,
                                      BBL::PrintParams      params,
                                      BBL::OnUpdateStatusFn update_fn,
                                      BBL::WasCancelledFn   cancel_fn,
                                      BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_cloud_print_job(params, update_fn, cancel_fn,
                                  /*use_lan_channel=*/false);
}

OBN_ABI int bambu_network_start_local_print_with_record(void* agent,
                                                        BBL::PrintParams      params,
                                                        BBL::OnUpdateStatusFn update_fn,
                                                        BBL::WasCancelledFn   cancel_fn,
                                                        BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_local_print_with_record", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    // Native LAN print by default: an enveloped+signed project_file published
    // over the printer's LAN MQTT broker, with the 3mf staged via FTPS:990.
    // This is the firmware-validated path for H2/O-series (a project_file with
    // a plaintext `ftp:///` url; the earlier "task canceled" 50348044 was the
    // two-slash `ftp://` url-format bug in build_ftp_url, NOT a missing cloud
    // task — cloud create_task is a dead end here, 403). The cloud path stays
    // available as an explicit opt-in for the true-remote case.
    if (obn::config::current().force_hybrid_print) {
        OBN_INFO("start_local_print_with_record: force_hybrid_print set -> Path A "
                 "(LAN FTPS file + cloud-broker url_enc project_file)");
        return a->run_hybrid_print_job(params, update_fn, cancel_fn);
    }
    if (obn::config::current().force_cloud_print) {
        const bool lan_ch = obn::config::current().force_cloud_print_lan_channel;
        OBN_INFO("start_local_print_with_record: force_cloud_print set -> cloud path (channel=%s)",
                 lan_ch ? "lan" : "cloud");
        return a->run_cloud_print_job(params, update_fn, cancel_fn, lan_ch);
    }
    return a->run_local_print_job(params, update_fn, cancel_fn);
}

OBN_ABI int bambu_network_start_send_gcode_to_sdcard(void* agent,
                                                     BBL::PrintParams      params,
                                                     BBL::OnUpdateStatusFn update_fn,
                                                     BBL::WasCancelledFn   cancel_fn,
                                                     BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_send_gcode_to_sdcard", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_send_gcode_to_sdcard(params, update_fn, cancel_fn);
}

OBN_ABI int bambu_network_start_local_print(void* agent,
                                            BBL::PrintParams      params,
                                            BBL::OnUpdateStatusFn update_fn,
                                            BBL::WasCancelledFn   cancel_fn)
{
    log_print_params("start_local_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    // Default to the native LAN path. The "task canceled" (50348044) we chased
    // to the cloud was actually the two-slash `ftp://` url-format bug (see
    // build_ftp_url) — H2/O-series firmware needs the empty-authority
    // `ftp:///<basename>` form to locate the file it just staged over FTPS:990.
    // The cloud create_task path is a dead end (403: the app cert it wants is a
    // per-session key we can't mint), so force_cloud_print stays an explicit
    // opt-in only, off by default.
    if (obn::config::current().force_hybrid_print) {
        OBN_INFO("start_local_print: force_hybrid_print set -> Path A "
                 "(LAN FTPS file + cloud-broker url_enc project_file)");
        return a->run_hybrid_print_job(params, update_fn, cancel_fn);
    }
    if (obn::config::current().force_cloud_print) {
        const bool lan_ch = obn::config::current().force_cloud_print_lan_channel;
        OBN_INFO("start_local_print: force_cloud_print set -> routing via cloud path (channel=%s)",
                 lan_ch ? "lan" : "cloud");
        return a->run_cloud_print_job(params, update_fn, cancel_fn,
                                      /*use_lan_channel=*/lan_ch);
    }
    return a->run_local_print_job(params, update_fn, cancel_fn);
}

OBN_ABI int bambu_network_start_sdcard_print(void* agent,
                                             BBL::PrintParams      params,
                                             BBL::OnUpdateStatusFn update_fn,
                                             BBL::WasCancelledFn   cancel_fn)
{
    log_print_params("start_sdcard_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_sdcard_print_job(params, update_fn, cancel_fn);
}
