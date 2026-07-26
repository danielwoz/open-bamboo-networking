// liveview_capture — stream a printer's liveview camera to a playable .mp4.
//
// Reuses the OBN library end-to-end: cloud session + ttcode mint + the
// CameraSourceFactory transport (TUTK / Agora / JPEG). This tool adds only a
// self-contained ISO-BMFF (MP4) muxer for the H.264 Annex-B frames the source
// emits, so OBN keeps its no-codec-dependency property (no ffmpeg / libav).
//
// SAFETY: read-only. It only mints a camera ttcode and reads frames. It never
// sends any print / move / control / gcode / device command.

#include "obn/auth.hpp"
#include "obn/camera.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/identity_headers.hpp"
#include "obn/json_lite.hpp"
#include "obn/signing.hpp"

#include "camera/CameraSourceFactory.hpp"
#include "camera/ICameraSource.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/evp.h>

namespace cam = bambu_net::camera;

#define LOG(fmt, ...)  do { std::fprintf(stdout, "[liveview] " fmt "\n", ##__VA_ARGS__); std::fflush(stdout); } while (0)
#define ERR(fmt, ...)  do { std::fprintf(stderr, "[liveview] " fmt "\n", ##__VA_ARGS__); } while (0)

static std::string default_bambustudio_config_dir() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA")) {
        return (std::filesystem::path(appdata) / "BambuStudio").string();
    }
    if (const char* userprofile = std::getenv("USERPROFILE")) {
        return (std::filesystem::path(userprofile) / "AppData" / "Roaming" / "BambuStudio").string();
    }
    return ".";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) {
        return (std::filesystem::path(home) / "Library" / "Application Support" / "BambuStudio").string();
    }
    return ".";
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
        return (std::filesystem::path(xdg) / "BambuStudio").string();
    }
    if (const char* home = std::getenv("HOME")) {
        return (std::filesystem::path(home) / ".config" / "BambuStudio").string();
    }
    return ".";
#endif
}

static std::vector<uint8_t> load_network_engine_key(const std::string& config_dir) {
    std::filesystem::path key_path = std::filesystem::path(config_dir) / "network_engine.key";
    std::string def_dir = default_bambustudio_config_dir();
    if (!std::filesystem::exists(key_path) && config_dir != def_dir) {
        std::filesystem::path alt_path = std::filesystem::path(def_dir) / "network_engine.key";
        if (std::filesystem::exists(alt_path)) {
            key_path = alt_path;
        }
    }

    if (!std::filesystem::exists(key_path)) {
        ERR("network_engine.key not found in %s", key_path.parent_path().string().c_str());
        return {};
    }

    std::ifstream ifs(key_path, std::ios::binary);
    if (!ifs.is_open()) {
        ERR("failed to open %s", key_path.string().c_str());
        return {};
    }

    std::string raw_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    if (raw_content.size() == 16) {
        return std::vector<uint8_t>(raw_content.begin(), raw_content.end());
    }

    std::string trimmed = raw_content;
    while (!trimmed.empty() && (trimmed.back() == '\r' || trimmed.back() == '\n' || trimmed.back() == ' ' || trimmed.back() == '\t')) {
        trimmed.pop_back();
    }
    size_t start = 0;
    while (start < trimmed.size() && (trimmed[start] == ' ' || trimmed[start] == '\t' || trimmed[start] == '\r' || trimmed[start] == '\n')) {
        start++;
    }
    if (start > 0) trimmed = trimmed.substr(start);

    if (trimmed.size() == 16) {
        return std::vector<uint8_t>(trimmed.begin(), trimmed.end());
    }

    if (trimmed.size() == 32) {
        bool is_hex = true;
        std::vector<uint8_t> bytes;
        bytes.reserve(16);
        for (size_t i = 0; i < 32; i += 2) {
            char h1 = trimmed[i];
            char h2 = trimmed[i+1];
            if (!std::isxdigit(static_cast<unsigned char>(h1)) || !std::isxdigit(static_cast<unsigned char>(h2))) {
                is_hex = false;
                break;
            }
            uint8_t b = static_cast<uint8_t>(std::stoi(trimmed.substr(i, 2), nullptr, 16));
            bytes.push_back(b);
        }
        if (is_hex && bytes.size() == 16) {
            return bytes;
        }
    }

    ERR("invalid network_engine.key in %s (expected 16 bytes or 32 hex characters)", key_path.string().c_str());
    return {};
}

// ---------------------------------------------------------------------------
// SIGINT: flip an atomic; the frame loop finalises cleanly.
// ---------------------------------------------------------------------------
static std::atomic<bool> g_stop{false};
static void on_sigint(int) { g_stop.store(true); }

// ---------------------------------------------------------------------------
// Big-endian byte emitters onto a byte vector (box builders).
// ---------------------------------------------------------------------------
static void put_u8 (std::vector<uint8_t>& b, uint8_t  v) { b.push_back(v); }
static void put_u16(std::vector<uint8_t>& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); }
static void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(v >> 24); b.push_back((v >> 16) & 0xff);
    b.push_back((v >> 8) & 0xff); b.push_back(v & 0xff);
}
static void put_bytes(std::vector<uint8_t>& b, const uint8_t* p, size_t n) { b.insert(b.end(), p, p + n); }
static void put_str4(std::vector<uint8_t>& b, const char* s) { b.insert(b.end(), s, s + 4); }

// A full box: [size][type][payload]. Patches the leading size once complete.
static std::vector<uint8_t> box(const char* type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> b;
    put_u32(b, static_cast<uint32_t>(8 + payload.size()));
    put_str4(b, type);
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

// ---------------------------------------------------------------------------
// Annex-B start-code scanning: yields NAL units with the start code stripped.
// ---------------------------------------------------------------------------
struct Nal { const uint8_t* data; size_t len; };

static std::vector<Nal> split_annexb(const uint8_t* p, size_t n) {
    std::vector<Nal> nals;
    size_t i = 0;
    // Find first start code.
    auto is_start = [&](size_t k, int& sc) -> bool {
        if (k + 3 <= n && p[k] == 0 && p[k+1] == 0 && p[k+2] == 1) { sc = 3; return true; }
        if (k + 4 <= n && p[k] == 0 && p[k+1] == 0 && p[k+2] == 0 && p[k+3] == 1) { sc = 4; return true; }
        return false;
    };
    int sc = 0;
    while (i < n && !is_start(i, sc)) ++i;
    while (i < n) {
        i += sc;                       // step over this start code
        size_t start = i;
        int sc2 = 0;
        while (i < n && !is_start(i, sc2)) ++i;
        if (i > start) nals.push_back({p + start, i - start});
        sc = sc2;
    }
    return nals;
}

static inline int nal_type(const Nal& nal) { return nal.len ? (nal.data[0] & 0x1f) : -1; }

// ---------------------------------------------------------------------------
// Minimal H.264 MP4 (ISO-BMFF) writer.
//   ftyp | mdat(streamed AVCC samples) | moov
// The mdat box size is patched at close via seek. Only the per-sample table is
// held in memory; sample payloads stream straight to disk.
// ---------------------------------------------------------------------------
class Mp4Writer {
public:
    bool open(const std::string& path) {
        f_ = std::fopen(path.c_str(), "wb+");
        if (!f_) return false;
        // ftyp
        std::vector<uint8_t> ft;
        put_str4(ft, "isom");
        put_u32(ft, 0x200);            // minor version
        put_str4(ft, "isom");
        put_str4(ft, "iso2");
        put_str4(ft, "avc1");
        put_str4(ft, "mp41");
        auto ftyp = box("ftyp", ft);
        std::fwrite(ftyp.data(), 1, ftyp.size(), f_);
        // mdat header placeholder (size patched at close).
        mdat_size_pos_ = std::ftell(f_);
        uint8_t hdr[8] = {0,0,0,0,'m','d','a','t'};
        std::fwrite(hdr, 1, 8, f_);
        chunk_offset_ = static_cast<uint64_t>(std::ftell(f_));
        return true;
    }

    void set_params(const std::vector<uint8_t>& sps, const std::vector<uint8_t>& pps,
                    int w, int h) {
        if (!sps.empty()) sps_ = sps;
        if (!pps.empty()) pps_ = pps;
        if (w > 0) width_ = w;
        if (h > 0) height_ = h;
    }

    // Append one access unit (Annex-B). Drops SPS/PPS NALs from the sample data
    // (they live in avcC); captures them if not already known.
    void add_frame(const uint8_t* p, size_t n, int64_t pts_us, bool keyframe) {
        std::vector<uint8_t> sample;
        for (const Nal& nal : split_annexb(p, n)) {
            int t = nal_type(nal);
            if (t == 7) { if (sps_.empty()) sps_.assign(nal.data, nal.data + nal.len); continue; }
            if (t == 8) { if (pps_.empty()) pps_.assign(nal.data, nal.data + nal.len); continue; }
            if (t == 9) continue;      // access-unit delimiter: not needed in AVCC
            put_u32(sample, static_cast<uint32_t>(nal.len));
            put_bytes(sample, nal.data, nal.len);
        }
        if (sample.empty()) return;
        std::fwrite(sample.data(), 1, sample.size(), f_);
        sizes_.push_back(static_cast<uint32_t>(sample.size()));
        pts_.push_back(pts_us);
        sync_.push_back(keyframe);
        mdat_payload_ += sample.size();
    }

    size_t frames() const { return sizes_.size(); }

    // Finalise: patch mdat size, then append moov. `fps` is a duration fallback.
    bool close(int fps) {
        if (!f_) return false;
        // Patch mdat size.
        uint64_t mdat_box_size = 8 + mdat_payload_;
        std::fseek(f_, mdat_size_pos_, SEEK_SET);
        uint8_t sz[4] = { uint8_t(mdat_box_size >> 24), uint8_t(mdat_box_size >> 16),
                          uint8_t(mdat_box_size >> 8),  uint8_t(mdat_box_size) };
        std::fwrite(sz, 1, 4, f_);
        std::fseek(f_, 0, SEEK_END);

        const uint32_t kTimescale = 90000;
        // Per-sample durations from pts deltas; fallback for the last (and any
        // non-increasing) delta.
        uint32_t fallback = fps > 0 ? (kTimescale / static_cast<uint32_t>(fps)) : 3000;
        std::vector<uint32_t> durs(sizes_.size(), fallback);
        for (size_t i = 0; i + 1 < pts_.size(); ++i) {
            int64_t d = pts_[i+1] - pts_[i];
            if (d > 0) {
                uint32_t ticks = static_cast<uint32_t>(d * 9 / 100);   // us -> 90kHz
                durs[i] = ticks ? ticks : 1;   // keep cumulative pts strictly increasing
            }
        }
        uint64_t total_ticks = 0;
        for (uint32_t d : durs) total_ticks += d;

        auto moov = build_moov(kTimescale, durs, total_ticks);
        std::fwrite(moov.data(), 1, moov.size(), f_);
        std::fclose(f_);
        f_ = nullptr;
        return true;
    }

    uint64_t mdat_bytes() const { return mdat_payload_; }

private:
    std::vector<uint8_t> build_avcc() const {
        std::vector<uint8_t> a;
        put_u8(a, 1);                                  // configurationVersion
        put_u8(a, sps_.size() > 1 ? sps_[1] : 0x42);   // AVCProfileIndication
        put_u8(a, sps_.size() > 2 ? sps_[2] : 0x00);   // profile_compatibility
        put_u8(a, sps_.size() > 3 ? sps_[3] : 0x28);   // AVCLevelIndication
        put_u8(a, 0xff);                               // lengthSizeMinusOne = 3
        put_u8(a, 0xe1);                               // numOfSequenceParameterSets = 1
        put_u16(a, static_cast<uint16_t>(sps_.size()));
        put_bytes(a, sps_.data(), sps_.size());
        put_u8(a, 1);                                  // numOfPictureParameterSets
        put_u16(a, static_cast<uint16_t>(pps_.size()));
        put_bytes(a, pps_.data(), pps_.size());
        return a;
    }

    std::vector<uint8_t> build_stbl(const std::vector<uint32_t>& durs) const {
        // stsd -> avc1 -> avcC
        std::vector<uint8_t> avc1;
        put_bytes(avc1, (const uint8_t*)"\0\0\0\0\0\0", 6); // reserved
        put_u16(avc1, 1);                                    // data_reference_index
        put_u16(avc1, 0); put_u16(avc1, 0);                  // pre_defined, reserved
        for (int i = 0; i < 3; ++i) put_u32(avc1, 0);        // pre_defined[3]
        put_u16(avc1, static_cast<uint16_t>(width_));
        put_u16(avc1, static_cast<uint16_t>(height_));
        put_u32(avc1, 0x00480000);                           // horizresolution 72dpi
        put_u32(avc1, 0x00480000);                           // vertresolution 72dpi
        put_u32(avc1, 0);                                    // reserved
        put_u16(avc1, 1);                                    // frame_count
        for (int i = 0; i < 32; ++i) put_u8(avc1, 0);        // compressorname
        put_u16(avc1, 0x0018);                               // depth
        put_u16(avc1, 0xffff);                               // pre_defined
        auto avcc = box("avcC", build_avcc());
        avc1.insert(avc1.end(), avcc.begin(), avcc.end());
        auto avc1box = box("avc1", avc1);

        std::vector<uint8_t> stsd;
        put_u32(stsd, 0);                                    // version+flags
        put_u32(stsd, 1);                                    // entry_count
        stsd.insert(stsd.end(), avc1box.begin(), avc1box.end());

        // stts (run-length compressed)
        std::vector<uint8_t> stts_entries;
        uint32_t stts_count = 0;
        for (size_t i = 0; i < durs.size();) {
            size_t j = i;
            while (j < durs.size() && durs[j] == durs[i]) ++j;
            put_u32(stts_entries, static_cast<uint32_t>(j - i));
            put_u32(stts_entries, durs[i]);
            ++stts_count;
            i = j;
        }
        std::vector<uint8_t> stts;
        put_u32(stts, 0);
        put_u32(stts, stts_count);
        stts.insert(stts.end(), stts_entries.begin(), stts_entries.end());

        // stss (sync samples, 1-based)
        std::vector<uint8_t> stss_entries;
        uint32_t sync_count = 0;
        for (size_t i = 0; i < sync_.size(); ++i)
            if (sync_[i]) { put_u32(stss_entries, static_cast<uint32_t>(i + 1)); ++sync_count; }
        std::vector<uint8_t> stss;
        put_u32(stss, 0);
        put_u32(stss, sync_count);
        stss.insert(stss.end(), stss_entries.begin(), stss_entries.end());

        // stsz (per-sample sizes)
        std::vector<uint8_t> stsz;
        put_u32(stsz, 0);
        put_u32(stsz, 0);                                    // sample_size 0 => table follows
        put_u32(stsz, static_cast<uint32_t>(sizes_.size()));
        for (uint32_t s : sizes_) put_u32(stsz, s);

        // stsc: all samples in one chunk
        std::vector<uint8_t> stsc;
        put_u32(stsc, 0);
        put_u32(stsc, 1);
        put_u32(stsc, 1);                                    // first_chunk
        put_u32(stsc, static_cast<uint32_t>(sizes_.size())); // samples_per_chunk
        put_u32(stsc, 1);                                    // sample_description_index

        // stco: single chunk offset (32-bit; falls back handled by co64 if huge)
        std::vector<uint8_t> stco;
        put_u32(stco, 0);
        put_u32(stco, 1);
        put_u32(stco, static_cast<uint32_t>(chunk_offset_));

        std::vector<uint8_t> stbl;
        auto append = [&](const std::vector<uint8_t>& b) { stbl.insert(stbl.end(), b.begin(), b.end()); };
        append(box("stsd", stsd));
        append(box("stts", stts));
        if (sync_count) append(box("stss", stss));
        append(box("stsz", stsz));
        append(box("stsc", stsc));
        append(box("stco", stco));
        return box("stbl", stbl);
    }

    std::vector<uint8_t> build_moov(uint32_t timescale,
                                    const std::vector<uint32_t>& durs,
                                    uint64_t total_ticks) const {
        const uint32_t movie_ts = 1000;
        uint32_t movie_dur = static_cast<uint32_t>(total_ticks * movie_ts / timescale);

        // mvhd
        std::vector<uint8_t> mvhd;
        put_u32(mvhd, 0);
        put_u32(mvhd, 0); put_u32(mvhd, 0);       // creation/modification time
        put_u32(mvhd, movie_ts);
        put_u32(mvhd, movie_dur);
        put_u32(mvhd, 0x00010000);                // rate 1.0
        put_u16(mvhd, 0x0100);                    // volume 1.0
        put_u16(mvhd, 0);                         // reserved
        put_u32(mvhd, 0); put_u32(mvhd, 0);       // reserved
        const uint32_t ident[9] = {0x10000,0,0, 0,0x10000,0, 0,0,0x40000000};
        for (uint32_t m : ident) put_u32(mvhd, m);
        for (int i = 0; i < 6; ++i) put_u32(mvhd, 0); // pre_defined
        put_u32(mvhd, 2);                         // next_track_ID

        // tkhd
        std::vector<uint8_t> tkhd;
        put_u32(tkhd, 0x0000000f);                // flags: enabled+in movie+preview
        put_u32(tkhd, 0); put_u32(tkhd, 0);       // times
        put_u32(tkhd, 1);                         // track_ID
        put_u32(tkhd, 0);                         // reserved
        put_u32(tkhd, movie_dur);
        put_u32(tkhd, 0); put_u32(tkhd, 0);       // reserved
        put_u16(tkhd, 0);                         // layer
        put_u16(tkhd, 0);                         // alternate_group
        put_u16(tkhd, 0);                         // volume (0 for video)
        put_u16(tkhd, 0);                         // reserved
        for (uint32_t m : ident) put_u32(tkhd, m);
        put_u32(tkhd, static_cast<uint32_t>(width_)  << 16);
        put_u32(tkhd, static_cast<uint32_t>(height_) << 16);

        // mdhd
        std::vector<uint8_t> mdhd;
        put_u32(mdhd, 0);
        put_u32(mdhd, 0); put_u32(mdhd, 0);
        put_u32(mdhd, timescale);
        put_u32(mdhd, static_cast<uint32_t>(total_ticks));
        put_u16(mdhd, 0x55c4);                    // language 'und'
        put_u16(mdhd, 0);

        // hdlr
        std::vector<uint8_t> hdlr;
        put_u32(hdlr, 0);
        put_u32(hdlr, 0);                         // pre_defined
        put_str4(hdlr, "vide");
        put_u32(hdlr, 0); put_u32(hdlr, 0); put_u32(hdlr, 0);
        const char* name = "VideoHandler";
        put_bytes(hdlr, (const uint8_t*)name, std::strlen(name) + 1);

        // vmhd
        std::vector<uint8_t> vmhd;
        put_u32(vmhd, 0x00000001);
        put_u16(vmhd, 0);                         // graphicsmode
        put_u16(vmhd, 0); put_u16(vmhd, 0); put_u16(vmhd, 0); // opcolor

        // dref -> url self-contained
        std::vector<uint8_t> url;
        put_u32(url, 0x00000001);                 // flags: self-contained
        std::vector<uint8_t> dref;
        put_u32(dref, 0);
        put_u32(dref, 1);
        auto urlbox = box("url ", url);
        dref.insert(dref.end(), urlbox.begin(), urlbox.end());

        std::vector<uint8_t> dinf = box("dref", dref);

        std::vector<uint8_t> minf;
        { auto b = box("vmhd", vmhd); minf.insert(minf.end(), b.begin(), b.end()); }
        { auto b = box("dinf", dinf); minf.insert(minf.end(), b.begin(), b.end()); }
        { auto b = build_stbl(durs); minf.insert(minf.end(), b.begin(), b.end()); }

        std::vector<uint8_t> mdia;
        { auto b = box("mdhd", mdhd); mdia.insert(mdia.end(), b.begin(), b.end()); }
        { auto b = box("hdlr", hdlr); mdia.insert(mdia.end(), b.begin(), b.end()); }
        { auto b = box("minf", minf); mdia.insert(mdia.end(), b.begin(), b.end()); }

        std::vector<uint8_t> trak;
        { auto b = box("tkhd", tkhd); trak.insert(trak.end(), b.begin(), b.end()); }
        { auto b = box("mdia", mdia); trak.insert(trak.end(), b.begin(), b.end()); }

        std::vector<uint8_t> moov;
        { auto b = box("mvhd", mvhd); moov.insert(moov.end(), b.begin(), b.end()); }
        { auto b = box("trak", trak); moov.insert(moov.end(), b.begin(), b.end()); }
        return box("moov", moov);
    }

    std::FILE* f_ = nullptr;
    long       mdat_size_pos_ = 0;
    uint64_t   chunk_offset_  = 0;
    uint64_t   mdat_payload_  = 0;
    std::vector<uint32_t> sizes_;
    std::vector<int64_t>  pts_;
    std::vector<bool>     sync_;
    std::vector<uint8_t>  sps_, pps_;
    int width_ = 1920, height_ = 1080;
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
static void usage() {
    std::fprintf(stderr,
        "liveview_capture — stream a printer liveview to an .mp4\n\n"
        "TUTK / cloud mint (H2/X1):\n"
        "  liveview_capture --dev-id <serial> --out <file.mp4>\n"
        "        [--config-dir <dir>] [--access-token <t> --user-id <u> --region <r>]\n"
        "        [--seconds N] [--max-frames N]\n\n"
        "JPEG models (A1/P1/N-series, no cloud mint):\n"
        "  liveview_capture --lan-ip <ip> --access-code <code> --model <model>\n"
        "        --dev-id <serial> --out <file.mp4> [--seconds N] [--max-frames N]\n");
}

static std::string arg_val(int& i, int argc, char** argv) {
    if (i + 1 >= argc) { ERR("missing value for %s", argv[i]); std::exit(2); }
    return argv[++i];
}

int main(int argc, char** argv) {
    std::string dev_id, out, config_dir, access_token, user_id, region = "us";
    std::string lan_ip, access_code, model;
    int seconds = 0, max_frames = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--dev-id")       dev_id       = arg_val(i, argc, argv);
        else if (a == "--out")          out          = arg_val(i, argc, argv);
        else if (a == "--config-dir")   config_dir   = arg_val(i, argc, argv);
        else if (a == "--access-token") access_token = arg_val(i, argc, argv);
        else if (a == "--user-id")      user_id      = arg_val(i, argc, argv);
        else if (a == "--region")       region       = arg_val(i, argc, argv);
        else if (a == "--lan-ip")       lan_ip       = arg_val(i, argc, argv);
        else if (a == "--access-code")  access_code  = arg_val(i, argc, argv);
        else if (a == "--model")        model        = arg_val(i, argc, argv);
        else if (a == "--seconds")      seconds      = std::atoi(arg_val(i, argc, argv).c_str());
        else if (a == "--max-frames")   max_frames   = std::atoi(arg_val(i, argc, argv).c_str());
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else { ERR("unknown argument: %s", a.c_str()); usage(); return 2; }
    }

    if (dev_id.empty() || out.empty()) { ERR("--dev-id and --out are required"); usage(); return 2; }

    if (config_dir.empty()) {
        config_dir = default_bambustudio_config_dir();
    }
    // Sets obn::config::current() so signing finds slicer_key.pem / slicer_cert_id
    // and cloud endpoints resolve per obn.conf.
    obn::config::load_or_create(config_dir);
    obn::http::global_init();

    obn::camera::CameraSpec spec;
    spec.dev_id = dev_id;

    if (!lan_ip.empty()) {
        // JPEG path: no cloud mint.
        spec.lan_ip      = lan_ip;
        spec.access_code = access_code;
        spec.model       = model;
        LOG("JPEG path: %s @ %s (model=%s)", dev_id.c_str(), lan_ip.c_str(), model.c_str());
    } else {
        // TUTK mint path.
        obn::auth::Store store(obn::config::path_in_dir("obn.auth.json"));
        store.load();
        obn::auth::Session sess = store.snapshot();
        if (!access_token.empty()) sess.access_token = access_token;
        if (!user_id.empty())      sess.user_id      = user_id;
        if (!region.empty())       sess.region       = region;

        // Fallback: if obn.auth.json is empty, try BambuNetworkEngine.conf
        if (sess.access_token.empty() || sess.user_id.empty()) {
            std::string conf_path = config_dir + "/BambuNetworkEngine.conf";
            if (std::filesystem::exists(conf_path)) {
                LOG("obn.auth.json empty, trying BambuNetworkEngine.conf fallback");
                std::vector<uint8_t> key = load_network_engine_key(config_dir);
                if (key.size() == 16) {
                    std::ifstream ifs(conf_path, std::ios::binary);
                    if (ifs.is_open()) {
                        // Read the encrypted conf file
                        std::vector<uint8_t> conf_data((std::istreambuf_iterator<char>(ifs)),
                                                       std::istreambuf_iterator<char>());
                        ifs.close();

                        std::vector<uint8_t> decrypted(conf_data.size());
                        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
                        EVP_CIPHER_CTX_set_padding(ctx, 0);  // no padding
                        int out_len = 0;
                        EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, conf_data.data(), conf_data.size());
                        EVP_CIPHER_CTX_free(ctx);
                        decrypted.resize(out_len);

                        // Remove trailing null bytes and parse JSON
                        std::string json_str(decrypted.begin(), decrypted.end());
                        // Strip trailing nulls
                        while (!json_str.empty() && json_str.back() == '\0') json_str.pop_back();

                        auto conf_root = obn::json::parse(json_str);
                        if (conf_root) {
                            std::string token = conf_root->find("user").find("token").as_string();
                            std::string uid    = conf_root->find("user").find("user_id").as_string();
                            if (!token.empty() && !uid.empty()) {
                                sess.access_token = token;
                                sess.user_id      = uid;
                                LOG("loaded session from BambuNetworkEngine.conf (user_id=%s)", uid.c_str());
                            }
                        }
                    }
                } else {
                    ERR("cannot decrypt BambuNetworkEngine.conf: network_engine.key is missing or invalid");
                }
            }
        }

        if (sess.access_token.empty() || sess.user_id.empty()) {
            ERR("no cloud session: supply --access-token/--user-id (and --region), "
                "or place a logged-in obn.auth.json in %s", config_dir.c_str());
            return 1;
        }

        // The ttcode endpoint authorizes the camera session only for the stock
        // client identity; a non-"BambuStudio" X-BBL-Client-Name is rejected
        // with HTTP 403 (same requirement as cloud /my/task). Present the stock
        // name for the mint unless the caller already pinned one via env.
        if (!std::getenv("BBL_CLIENT_NAME")) setenv("BBL_CLIENT_NAME", "BambuStudio", 1);

        auto headers = obn::bbl::identity_headers(sess.access_token, sess.user_id,
                                                  /*include_client_id=*/false,
                                                  /*with_content_type=*/true,
                                                  /*with_signing_headers=*/true);
        if (!headers.count("x-bbl-device-security-sign")) {
            ERR("WARNING: device_security_sign() is empty — no slicer key loaded; "
                "the mint will likely 403. Expected key at %s/slicer_key.pem",
                config_dir.c_str());
        }

        std::string url  = obn::cloud::api_host(sess.region) + "/v1/iot-service/api/user/ttcode";
        std::string body = "{\"dev_id\":\"" + dev_id + "\"}";
        LOG("minting camera ttcode: POST %s (region=%s)", url.c_str(), sess.region.c_str());
        auto resp = obn::http::post_json(url, body, headers);
        if (!resp.error.empty()) { ERR("ttcode mint transport error: %s", resp.error.c_str()); return 1; }
        if (resp.status_code != 200) {
            ERR("ttcode mint failed: HTTP %ld body=%s", resp.status_code, resp.body.c_str());
            return 1;
        }
        auto root = obn::json::parse(resp.body);
        if (!root) { ERR("ttcode mint: unparseable response"); return 1; }
        std::string ttcode  = root->find("ttcode").as_string();
        std::string authkey = root->find("authkey").as_string();
        std::string passwd  = root->find("passwd").as_string();
        std::string rgn     = root->find("region").as_string();
        if (rgn.empty()) rgn = sess.region;
        if (ttcode.empty()) { ERR("ttcode mint: no ttcode in response: %s", resp.body.c_str()); return 1; }
        LOG("ttcode mint OK: HTTP 200, region=%s (ttcode/authkey/passwd redacted)", rgn.c_str());

        spec.camera_url = "bambu:///tutk?uid=" + ttcode +
                          "&authkey=" + authkey +
                          "&passwd="  + passwd  +
                          "&region="  + rgn     +
                          "&device="  + dev_id;
    }

    auto src = obn::camera::CameraSourceFactory().make(spec);
    if (!src || !src->open()) { ERR("failed to open camera source"); return 1; }

    auto info = src->info();
    bool is_h264 = info.codec == cam::ICameraSource::Codec::H264_AnnexB;
    LOG("stream open: %dx%d fps=%d codec=%s sps=%zuB pps=%zuB",
        info.width, info.height, info.fps,
        is_h264 ? "H264" : "MJPEG", info.sps.size(), info.pps.size());

    std::signal(SIGINT, on_sigint);

    auto t0 = std::chrono::steady_clock::now();
    size_t nframes = 0, nkey = 0;
    uint64_t nbytes = 0;

    if (!is_h264) {
        // MotionJpeg: this muxer is H.264-only. Write concatenated JPEGs.
        std::string mj = out + ".mjpeg";
        std::FILE* jf = std::fopen(mj.c_str(), "wb");
        if (!jf) { ERR("cannot open %s", mj.c_str()); return 1; }
        LOG("NOTE: MJPEG model — writing concatenated JPEGs to %s "
            "(mp4 muxing is H.264-only in v1).", mj.c_str());
        while (!g_stop.load()) {
            auto fr = src->next_frame(1000);
            if (!fr) { if (!src->is_open()) break; else continue; }
            std::fwrite(fr->nal_data.data(), 1, fr->nal_data.size(), jf);
            ++nframes; ++nkey; nbytes += fr->nal_data.size();
            auto el = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::steady_clock::now() - t0).count();
            if (seconds && el >= seconds) break;
            if (max_frames && (int)nframes >= max_frames) break;
        }
        std::fclose(jf);
        double wall = std::chrono::duration<double>(
                          std::chrono::steady_clock::now() - t0).count();
        src->close();
        LOG("done: %zu frames, %llu bytes, %.1fs -> %s",
            nframes, (unsigned long long)nbytes, wall, mj.c_str());
        return nframes ? 0 : 1;
    }

    Mp4Writer mp4;
    if (!mp4.open(out)) { ERR("cannot open output %s", out.c_str()); return 1; }
    mp4.set_params(info.sps, info.pps, info.width, info.height);

    while (!g_stop.load()) {
        auto fr = src->next_frame(1000);
        if (!fr) {
            if (!src->is_open()) { LOG("end of stream"); break; }
            auto el = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::steady_clock::now() - t0).count();
            if (seconds && el >= seconds) break;
            continue;
        }
        // The TUTK device timestamp increments ~1ms/frame regardless of the
        // real delivery rate (it behaves as a frame counter), so it cannot time
        // the movie. Use wall-clock arrival relative to the first frame, which
        // reproduces the true real-time playback rate.
        int64_t arrival_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now() - t0).count();
        mp4.add_frame(fr->nal_data.data(), fr->nal_data.size(), arrival_us, fr->is_keyframe);
        ++nframes;
        if (fr->is_keyframe) ++nkey;
        nbytes += fr->nal_data.size();

        auto el = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::steady_clock::now() - t0).count();
        if (seconds && el >= seconds) break;
        if (max_frames && (int)nframes >= max_frames) break;
    }

    src->close();
    mp4.close(info.fps);
    double wall = std::chrono::duration<double>(
                      std::chrono::steady_clock::now() - t0).count();

    LOG("summary: frames=%zu keyframes=%zu sample_bytes=%llu wall=%.1fs out=%s",
        mp4.frames(), nkey, (unsigned long long)mp4.mdat_bytes(), wall, out.c_str());
    if (mp4.frames() == 0) { ERR("no frames captured"); return 1; }
    return 0;
}
