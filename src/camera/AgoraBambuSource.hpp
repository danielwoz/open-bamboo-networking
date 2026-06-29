// SPDX-License-Identifier: AGPL-3.0-only
//
// AgoraBambuSource — open-source BambuSourceHandle implementation for the
// Agora cloud-relay camera path.
//
// Protocol derived by reverse-engineering libBambuSource.so with Ghidra.
// No code from that binary appears here; only the protocol knowledge
// (URL parameter names, region codes, RDT message format) was extracted.
//
// Runtime dependency: libagora_rtc_sdk.so (proprietary, dlopen'd at runtime).
// This file and AgoraBambuSource.cpp are AGPL-3.0 open source.
//
// URL format consumed:
//   bambu:///agora?app=<APP_ID>
//                 &channel=<CHANNEL_NAME>
//                 &token=<AGORA_TOKEN>
//                 &user=<UID_uint32>
//                 &region=<cn|eu|na|us>
//                 &device=<SN>
//                 &dev_ver=<DEVICE_VER>
//                 &net_ver=<NET_VER>
//                 &cli_id=<CLIENT_ID>
//                 &cli_ver=<CLIENT_VER>
//                 [&refresh_url=<HEX_FNPTR>]   // token-refresh callback
//                 [&auxiliary_enable=1]          // use auxiliary refresh path

#pragma once

#include "BambuSourceHandle.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bambu_net {
namespace camera {

// Region codes that libBambuSource maps from the "region" URL param.
enum class AgoraRegion : uint32_t {
    Default = 0xFFFFFFFF,  // let SDK decide
    CN      = 1,
    NA      = 2,
    EU      = 4,
    US      = 0x800,
};

AgoraRegion agora_region_from_string(const std::string& s);

// Parsed representation of a bambu:///agora?... URL.
struct AgoraUrl {
    std::string   app_id;       // Agora App ID
    std::string   channel;      // Agora channel name / TUTK relay ID
    std::string   token;        // Agora auth token
    std::string   passwd;       // printer passwd; PSK = SHA256(passwd) for TUTK relay DTLS
    uint32_t      uid     = 0;  // local user ID (numeric, Agora-SDK field)
    std::string   tutk_uid;     // TUTK device UID (20-char string from cloud API)
    AgoraRegion   region  = AgoraRegion::Default;
    std::string   device;       // printer serial number
    std::string   dev_ver;
    std::string   net_ver;
    std::string   cli_id;
    std::string   cli_ver;
    // Token-refresh: either a function pointer encoded as hex, or auxiliary path.
    uintptr_t     refresh_fn  = 0;
    bool          auxiliary   = false;

    static bool parse(const std::string& url, AgoraUrl& out, std::string& err);
};

// -----------------------------------------------------------------------
// Forward declaration of Agora SDK interfaces.
// Declared here as abstract vtable shims — we dlopen the SDK and call
// through function pointers.  No Agora header is needed at compile time.
// Vtable layout verified against Agora SDK 4.x (used by BambuStudio).
// -----------------------------------------------------------------------

struct IAgoraEventHandler;

struct IAgoraRtcEngine {
    // vtable slot 0 — destructor (unused; we call release() instead)
    virtual ~IAgoraRtcEngine() = default;

    // The actual vtable positions are SDK-version-specific.
    // We call through the factory pointer and use the public C methods
    // below to avoid hardcoding offsets.
    virtual int  queryInterface(int iid, void** inter) = 0;
    virtual void release(bool sync = false) = 0;
    virtual int  initialize(const void* ctx) = 0;       // RtcEngineContext*
    // ... (we use only what we need; the rest resolved at runtime)
};

// -----------------------------------------------------------------------
// Agora RTC engine — minimal dlopen wrapper.
// -----------------------------------------------------------------------

class AgoraRtcLib {
public:
    AgoraRtcLib() = default;
    ~AgoraRtcLib();

    AgoraRtcLib(const AgoraRtcLib&)            = delete;
    AgoraRtcLib& operator=(const AgoraRtcLib&) = delete;

    bool load(std::string* err = nullptr);
    bool loaded() const { return m_handle != nullptr && m_create_fn != nullptr; }

    // Allocate a new IRtcEngine. Caller must call release() when done.
    void* create_engine() const;

private:
    void* m_handle    = nullptr;
    void* m_create_fn = nullptr;  // createAgoraRtcEngine
};

// -----------------------------------------------------------------------
// Received H.264 frame (copied from the Agora video frame observer callback).
// -----------------------------------------------------------------------
struct AgoraVideoFrame {
    std::vector<uint8_t> data;
    int64_t  pts_us      = 0;
    bool     is_keyframe = false;
};

// -----------------------------------------------------------------------
// AgoraBambuSource — concrete BambuSourceHandle for Agora cloud relay.
// -----------------------------------------------------------------------

class AgoraBambuSource : public BambuSourceHandle {
public:
    // lib must outlive this object.
    explicit AgoraBambuSource(std::shared_ptr<AgoraRtcLib> lib);
    ~AgoraBambuSource() override;

    bool init() override;
    bool library_ready() const override;

    int  bambu_create(void** out_tunnel, const std::string& url) override;
    void bambu_destroy(void* tunnel) override;
    int  bambu_open(void* tunnel) override;
    void bambu_close(void* tunnel) override;
    int  bambu_start_stream(void* tunnel, bool video) override;
    int  bambu_start_stream_ex(void* tunnel, int type) override;
    int  bambu_send_message(void* tunnel, int ctrl,
                            const char* data, int len) override;
    void bambu_set_logger(void* tunnel, BambuSourceHandle::Logger logger, void* ctx) override;
    std::string bambu_get_last_error_msg() override;

    int  bambu_get_stream_count(void* tunnel) override;
    int  bambu_get_stream_info(void* tunnel, int index, void* info_out) override;
    int  bambu_read_sample(void* tunnel, void* sample_out) override;

private:
    std::shared_ptr<AgoraRtcLib> m_lib;
};

}  // namespace camera
}  // namespace bambu_net
