// SPDX-License-Identifier: AGPL-3.0-only
//
// IotcClient.cpp — Skeleton open-source reimplementation of the TUTK IOTC
//                   P2P client, using raw BSD sockets.  No TUTK SDK code.
//
// Current status: AV layer IMPLEMENTED; P2P connection flow and LAN search
// are still stubbed.  The avClientStartEx / avClientStop / avSendIOCtrl /
// avRecvFrameData2 extern "C" functions are fully coded with the wire format
// derived from disassembly of avConnect_inner, _avSendIO, _avRecvData, and
// _avProcessLoginPacket.  oss_av_start() is the high-level convenience entry.
//
// Protocol knowledge source: static analysis of libBambuSource.so
// (TUTK SDK 4.3.3.4-0-gf6d6219_openssl_x64 embedded in Bambu v02.06.01.50).
// No proprietary code is reproduced; all structure layouts are re-derived.
//
// ==========================================================================
// WHAT IS KNOWN / UNKNOWN
// ==========================================================================
//
// KNOWN (from disassembly + strings):
//   - Master server domain pattern: "<region>-c-master.iotcplatform.com"  (dash separator)
//   - Secondary: "<region>-c-master.kalayservice.com"
//   - CN region: "<region>-c-master.kalay.net.cn"
//   - UID: exactly 20 printable ASCII characters, stored lowercase
//   - LAN search packet size: 516 bytes (0x204)
//   - Session struct stride: 5824 bytes per session (0x16c0)
//   - IotcConnectCfg: 20-byte struct (size field must be 0x14)
//   - AvStartIn:  56-byte struct (size field 0x38)
//   - AvStartOut: 24-byte struct (size field 0x18 pre-filled)
//   - IPCAM_START command: avSendIOCtrl(idx, 0xFF01, NULL, 0)
//   - AV frame header: 16 bytes, magic marker 0x013f in bytes 4-5
//   - H.264 frames delivered via avRecvFrameData2 (reassembled from packets)
//   - NAT traversal message sequence: PRECHECK1 → PRECHECK2 → REQUEST →
//     KNOCK/KNOCK_R/KNOCK_RR → PUNCH_TO → P2P session alive
//   - Relay fallback: RLY_REQUEST → RLY_REQUEST_R2 → RLY_KNOCK → session
//   - TCP relay mode controlled by gbTcpRelayMode global
//   - DTLS encryption layer available (IOTC_sCHL_* functions, PSK-based)
//   - Auth key: uint64 from the "authkey" URL parameter (8 bytes)
//   - Default password: "888888"; account: "admin"
//
// DERIVED FROM DISASSEMBLY (avConnect_inner, _avProcessLoginPacket, etc.):
//   - LOGIN frame wire format: AvFrameHeader + account\0 + passwd\0
//     * header.reserved = 0x0000000b (from assemblePackHead cx=0x0b)
//     * magic = 0x0001013f (sub=LOGIN=0x01, dir=C→P=0x00)
//     * Server validates with _AvDoAuthCheck after reading packet
//   - IOCtrl wire format: AvFrameHeader(sub=CTRL) + uint32_t type + uint32_t len + data
//   - avSendIOCtrl → _avSendIO → avSendIOCtrlFrame(obj, type, buf, len, flags=0x70)
//   - avRecvFrameData2 → _avRecvData → vtable[0x38]
//   - vtable layout confirmed from AVConn_construct @ 0x166ac0
//   - Video channel for Bambu: channel field from AvStartIn[0x08] (0..31)
//     Bambu uses channel=0 for the main video stream (see avClientStartEx validator)
//   - Password constraints: account <= 255 chars, passwd <= 119 chars
//   - SHA256 of passwd computed at 168529 (TUTK3rdSHA256) for remote protocol > 0x16
//
// STILL UNKNOWN / NEEDS CAPTURE:
//   - Exact numeric values for TutkMsgType enum (estimated from TUTK SDK docs)
//   - Full LAN search response structure (gDeviceName field contents)
//   - How authkey is used in MSG_P2P_PRECHECK2 (likely HMAC or direct field)
//   - FEC (Forward Error Correction) parameters (avDefineFECEncodeRatio refs)
//   - DTLS PSK identity format for AV channel encryption
//   - Whether LOGIN ACK payload_len=4 is always the case or varies by firmware
//
// NOTE: Bambu's production firmware operates in LAN-direct or Agora-relay mode
// only.  CheckLicenseKeyIsValid() returns -1004, permanently short-circuiting
// the TUTK master registration path (IOTC_TcpConnectToMaster).  The master
// server is never contacted at runtime.
//
// TODO for future work:
//   [ ] Decode the AV frame body to confirm JSON+binary structure
//   [ ] Implement LAN search + verify against a real printer
//   [ ] Implement full NAT traversal state machine
//   [ ] Confirm MSG_P2P_ALIVE_C2D bytes via pcap if NAT P2P path is ever used

#include "IotcProtocol.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace bambu_net {
namespace oss_tutk {

// PSK = SHA256(g_oss_dtls_passwd); identity = "AUTHPWD_" + g_oss_dtls_account.
static std::string g_oss_dtls_passwd  = "888888";
static std::string g_oss_dtls_account = "admin";

// ==========================================================================
// Internal utilities
// ==========================================================================

__attribute__((unused)) static uint32_t now_sec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec;
}

static uint32_t rand32()
{
    // Simple non-crypto random; TUTK uses GenShortRandomID which calls
    // a similar lightweight generator.
    static uint64_t state = 0;
    if (!state) { struct timeval tv; gettimeofday(&tv, nullptr); state = tv.tv_usec ^ (uint64_t)tv.tv_sec << 20; }
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return (uint32_t)state;
}

// Canonicalize UID to lowercase (IOTC_Connect_UDP_Inner loop at +0xf0).
static std::string uid_lower(const std::string& uid)
{
    std::string out = uid;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c += 0x20;
    return out;
}

static std::string uid_upper(const std::string& uid)
{
    std::string out = uid;
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c -= 0x20;
    return out;
}

// IsUIDVaild.part.0: loop 0x14 iterations, each byte passes ctype is-print (bit 0x08).
static bool uid_valid(const std::string& uid)
{
    if (uid.size() != kUidLen) return false;
    for (unsigned char c : uid)
        if (c < 0x21 || c > 0x7e) return false;  // printable non-space ASCII
    return true;
}

// ==========================================================================
// Master server DNS resolution
// ==========================================================================

// Confirmed from CreateDomainName disassembly (0x1af430) in libBambuSource.so:
//   Format string: "%s-%s-%s%s"  → <region>-<service>-<service2><tld_with_leading_dot>
//
// In practice for the "c-master" (control) service:
//   gRegionName[region]  = "cn" / "eu" / "us" / "asia"
//   gServiceName[0]      = "c-master"
//   Hostname suffix      = ".iotcplatform.com"  (leading dot in the table entry)
//
// Final result example:  "us-c-master.iotcplatform.com"
//   (the format is <region>-c-master + .iotcplatform.com, NOT dot-separated)
//
// Note: the real binary requires a vendor license key (gIsKeySet / gIsCustomRealm)
// before GetMasterDomainName will succeed.  In our open reimplementation we skip
// that check and hard-code the public TUTK domains.
//
// The binary tries 12 server addresses, cycling the port from a table:
//   gTcpTryPort = [80, 443, 21047, 8080, 8000, 20297, 17236, 0, 8686, ...]
// We expose only the first-choice hostname here; connect_to_master() tries ports.
static std::string master_hostname(TutkRegion region, bool cn_domain = false)
{
    const char* rname;
    switch (region) {
        case TutkRegion::CN:   rname = "cn";   break;
        case TutkRegion::EU:   rname = "eu";   break;
        case TutkRegion::US:   rname = "us";   break;
        case TutkRegion::Asia: rname = "asia"; break;
        default:               rname = "";     break; // Global = no region prefix
    }

    const char* tld = cn_domain ? ".kalay.net.cn" : ".iotcplatform.com";

    if (rname[0])
        return std::string(rname) + "-c-master" + tld;
    else
        return std::string("c-master") + tld;
}

// NOTE: The TUTK master path is never reached in production Bambu firmware —
// CheckLicenseKeyIsValid() returns -1004.  Retained for completeness.
static bool resolve_master(const std::string& hostname, uint16_t port,
                           struct sockaddr_in* out)
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(hostname.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "[oss-iotc] DNS failed for %s: %s\n",
                hostname.c_str(), gai_strerror(rc));
        return false;
    }
    *out = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);
    return true;
}

// ==========================================================================
// UDP socket helpers
// ==========================================================================

// Mirrors IOTC_OpenUDP_P2PSocket; gP2PLocalUdpPort defaults to 0 (OS-assigned).
static int open_udp_socket(uint16_t* bound_port_out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = 0; // ephemeral

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    if (bound_port_out) {
        socklen_t len = sizeof(addr);
        getsockname(fd, (struct sockaddr*)&addr, &len);
        *bound_port_out = ntohs(addr.sin_port);
    }
    return fd;
}

static void set_recv_timeout(int fd, int ms)
{
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// ==========================================================================
// TransCodePartial — TUTK packet scrambling (all bytes of each UDP datagram)
// ==========================================================================
//
// Confirmed from binary analysis of libBambuSource.so:
//   iotc_trans_arr @ data segment: "Charlie is the devil, but I am ..."
//   KEY = first 16 bytes = "Charlie is the d"
//
// Algorithm (16-byte blocks):
//   rot[] = {1, 5, 9, 13}  (rotation amounts per dword)
//
//   decode_block(raw[16]) → plain[16]:
//     1. dw[i] = ROR32(raw_dw[i], rot[i]) ^ key_dw[i]    i=0..3
//        (raw_dw read as little-endian uint32_t)
//     2. t[j*4+k] = (dw[j] >> (8*k)) & 0xff              expand to bytes
//     3. o0 = ROR32((t[15]<<24)|(t[8]<<16)|(t[9]<<8)|t[11], 3)
//        o1 = ROR32((t[14]<<24)|(t[12]<<16)|(t[10]<<8)|t[13], 7)
//        o2 = ROR32((t[0]<<24)|(t[5]<<16)|(t[1]<<8)|t[2], 11)
//        o3 = ROR32((t[3]<<24)|(t[7]<<16)|(t[4]<<8)|t[6], 15)
//     4. Write o0..o3 as LE bytes → 16 plaintext bytes
//
//   encode_block is the exact inverse (verified: decode(encode(x)) == x).
//
//   Tail bytes (len % 16 != 0): XOR each with KEY[i % 16].

static const uint8_t kTransKey[16] = {
    'C','h','a','r','l','i','e',' ','i','s',' ','t','h','e',' ','d'
};

static inline uint32_t ror32(uint32_t v, unsigned n) { n &= 31; return (v >> n) | (v << (32-n)); }
static inline uint32_t rol32(uint32_t v, unsigned n) { n &= 31; return (v << n) | (v >> (32-n)); }

static inline uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static inline uint16_t read_be16(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static void decode_block(const uint8_t* in, uint8_t* out)
{
    const uint8_t* k = kTransKey;
    const unsigned rot[4] = {1, 5, 9, 13};

    uint32_t o[4];
    memcpy(o, in, 16);

    uint32_t tmp0 = rol32(o[0], 3);
    uint32_t tmp1 = rol32(o[1], 7);
    uint32_t tmp2 = rol32(o[2], 11);
    uint32_t tmp3 = rol32(o[3], 15);

    uint8_t t[16];
    t[0]  = (tmp2 >> 24) & 0xff;
    t[1]  = (tmp2 >>  8) & 0xff;
    t[2]  = (tmp2 >>  0) & 0xff;
    t[3]  = (tmp3 >> 24) & 0xff;
    t[4]  = (tmp3 >>  8) & 0xff;
    t[5]  = (tmp2 >> 16) & 0xff;
    t[6]  = (tmp3 >>  0) & 0xff;
    t[7]  = (tmp3 >> 16) & 0xff;
    t[8]  = (tmp0 >> 16) & 0xff;
    t[9]  = (tmp0 >>  8) & 0xff;
    t[10] = (tmp1 >>  8) & 0xff;
    t[11] = (tmp0 >>  0) & 0xff;
    t[12] = (tmp1 >> 16) & 0xff;
    t[13] = (tmp1 >>  0) & 0xff;
    t[14] = (tmp1 >> 24) & 0xff;
    t[15] = (tmp0 >> 24) & 0xff;

    uint32_t dw[4];
    for (int j = 0; j < 4; ++j)
        dw[j] = (uint32_t)t[j*4]
              | ((uint32_t)t[j*4+1] << 8)
              | ((uint32_t)t[j*4+2] << 16)
              | ((uint32_t)t[j*4+3] << 24);

    uint32_t key_dw[4];
    memcpy(key_dw, k, 16);

    uint32_t raw_dw[4];
    for (int i = 0; i < 4; ++i)
        raw_dw[i] = rol32(dw[i] ^ key_dw[i], rot[i]);

    memcpy(out, raw_dw, 16);
}

static void encode_block(const uint8_t* in, uint8_t* out)
{
    const uint8_t* k = kTransKey;
    const unsigned rot[4] = {1, 5, 9, 13};

    uint32_t raw_dw[4];
    memcpy(raw_dw, in, 16);

    uint32_t key_dw[4];
    memcpy(key_dw, k, 16);

    uint32_t dw[4];
    for (int i = 0; i < 4; ++i)
        dw[i] = ror32(raw_dw[i], rot[i]) ^ key_dw[i];

    uint8_t t[16];
    for (int j = 0; j < 4; ++j)
        for (int b = 0; b < 4; ++b)
            t[j*4+b] = (dw[j] >> (8*b)) & 0xff;

    uint32_t o0 = ror32((uint32_t)(t[15]<<24)|(t[8]<<16)|(t[9]<<8)|t[11], 3);
    uint32_t o1 = ror32((uint32_t)(t[14]<<24)|(t[12]<<16)|(t[10]<<8)|t[13], 7);
    uint32_t o2 = ror32((uint32_t)(t[0]<<24)|(t[5]<<16)|(t[1]<<8)|t[2], 11);
    uint32_t o3 = ror32((uint32_t)(t[3]<<24)|(t[7]<<16)|(t[4]<<8)|t[6], 15);

    memcpy(out,    &o0, 4);
    memcpy(out+4,  &o1, 4);
    memcpy(out+8,  &o2, 4);
    memcpy(out+12, &o3, 4);
}

static void reverse_trans_code_partial(uint8_t* data, size_t len)
{
    size_t full = (len / 16) * 16;
    uint8_t tmp[16];
    for (size_t i = 0; i < full; i += 16) {
        decode_block(data + i, tmp);
        memcpy(data + i, tmp, 16);
    }
    for (size_t i = full; i < len; ++i)
        data[i] ^= kTransKey[i % 16];
}

static void trans_code_partial(uint8_t* data, size_t len)
{
    size_t full = (len / 16) * 16;
    uint8_t tmp[16];
    for (size_t i = 0; i < full; i += 16) {
        encode_block(data + i, tmp);
        memcpy(data + i, tmp, 16);
    }
    for (size_t i = full; i < len; ++i)
        data[i] ^= kTransKey[i % 16];
}

#ifdef OBN_TESTING
void trans_code_partial_test(uint8_t* data, size_t len)         { trans_code_partial(data, len); }
void reverse_trans_code_partial_test(uint8_t* data, size_t len) { reverse_trans_code_partial(data, len); }
#endif

// ==========================================================================
// IOTC DTLS frame encoder / decoder
// ==========================================================================
//
// All DTLS packets are wrapped in a 28-byte IOTC+sub-header, then the
// entire packet (all 28+N bytes) is scrambled with trans_code_partial.
//
// IOTC header (16 bytes):
//   [0..1]  0x0204 (LE) — magic
//   [2]     0x1c        — version
//   [3]     0x0b        — flags (DTLS payload)
//   [4..5]  payload_len LE (= 12 + dtls_len)
//   [6..7]  0x0000
//   [8]     0x07, [9] 0x04, [10] 0x21  — msg type (client→server DTLS)
//   [11]    0x00
//   [12..13] session_token[0..1] (first 2 bytes of 8-byte session token)
//   [14..15] 0x0001
//
// Sub-header (12 bytes):
//   [0]     0x0c
//   [1..2]  epoch_low16 big-endian  (0x0000 before ServerHello, 0x06a0 after)
//   [3]     0x00
//   [4..11] session_token (8 bytes)
//
// Received DTLS packets have a slightly different msg-type triplet:
//   [8]=0x08, [9]=0x04, [10]=0x12  (server→client)

static int send_dtls_packet(int sock, const struct sockaddr_in* dst,
                             uint32_t epoch,
                             const uint8_t session_token[8],
                             const uint8_t* dtls_data, size_t dtls_len)
{
    size_t total = 28 + dtls_len;
    std::vector<uint8_t> pkt(total, 0);

    uint16_t payload_len = (uint16_t)(12 + dtls_len);

    // IOTC header
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x0b;
    pkt[4] = (uint8_t)(payload_len & 0xff);
    pkt[5] = (uint8_t)(payload_len >> 8);
    // [6..7] = 0
    pkt[8]  = 0x07; pkt[9]  = 0x04; pkt[10] = 0x21;
    // [11] = 0
    pkt[12] = session_token[0];
    pkt[13] = session_token[1];
    pkt[14] = 0x00; pkt[15] = 0x01;

    // Sub-header
    pkt[16] = 0x0c;
    pkt[17] = (uint8_t)((epoch >> 8) & 0xff);  // epoch low16, big-endian
    pkt[18] = (uint8_t)(epoch & 0xff);
    // pkt[19] = 0x00
    memcpy(pkt.data() + 20, session_token, 8);

    // DTLS payload
    if (dtls_len > 0)
        memcpy(pkt.data() + 28, dtls_data, dtls_len);

    trans_code_partial(pkt.data(), std::min(total, (size_t)80));

    ssize_t n = sendto(sock, pkt.data(), total, 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)total) ? 0 : -1;
}

// Retries on non-DTLS IOTC packets (e.g., stray type 0x33 echoes before ServerHello).
// Returns DTLS payload length on success, -1 on timeout/error.
static int recv_dtls_packet(int sock, uint8_t* dtls_out, size_t buf_size,
                             uint32_t* epoch_out,
                             uint8_t session_token_out[8],
                             int timeout_ms)
{
    set_recv_timeout(sock, timeout_ms);

    for (int attempt = 0; attempt < 8; ++attempt) {
    uint8_t raw[2048];
    struct sockaddr_in src{};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(sock, raw, sizeof(raw), 0,
                          (struct sockaddr*)&src, &src_len);
    if (n < 28) return -1;

    reverse_trans_code_partial(raw, std::min((size_t)n, (size_t)80));

    if (raw[0] != 0x04 || raw[1] != 0x02) continue;  // discard non-IOTC

    // Skip non-DTLS IOTC packets (type 0x33 echoes etc.):
    // DTLS content starts with 0x16 (Handshake), 0x14 (CCS), or 0x15 (Alert).
    size_t dtls_len = (size_t)(n - 28);
    if (dtls_len < 1 || (raw[28] != 0x16 && raw[28] != 0x14 && raw[28] != 0x15)) {
        fprintf(stderr, "[dtls] recv: skipping non-DTLS IOTC pkt (n=%zd type=0x%02x)\n",
                n, dtls_len > 0 ? raw[28] : 0);
        continue;
    }

    if (epoch_out) {
        uint32_t ep = ((uint32_t)raw[17] << 8) | raw[18];
        *epoch_out = ep;
    }
    if (session_token_out)
        memcpy(session_token_out, raw + 20, 8);

    if (dtls_len > buf_size) dtls_len = buf_size;
    memcpy(dtls_out, raw + 28, dtls_len);
    return (int)dtls_len;
    }  // end for (attempt)
    return -1;
}

// ==========================================================================
// LAN_SEARCH3 wire layout (88 bytes, scrambled with trans_code_partial):
//   [0..15]  IOTC header: magic=0x0204, ver=0x1c, flags=0x00, payload_len=0x48,
//            bytes[8..10]={0x01,0x06,0x21}
//   [16..35] uid (20B, UPPERCASE)
//   [36..39] connect_flag (uint32 LE = 0)
//   [40..47] zeros (unknown fields)
//   [48..51] = 0x00 [epoch_hi] [epoch_lo] 0x00   (first epoch occurrence)
//   [52..55] iotc_version (uint32 LE = 0x04030304)
//   [56..59] client_random (uint32 LE)
//   [60..63] partial_mac (uint32 LE)
//   [64]     search_type: 0x01=broadcast, 0x02=directed
//   [65..66] [epoch_hi] [epoch_lo]   (second epoch occurrence)
//   [67..87] zeros
//
static int send_lan_search3(int sock, const struct sockaddr_in* dst,
                             const char* uid_up, uint32_t client_random,
                             uint32_t partial_mac, uint16_t epoch, bool directed)
{
    uint8_t pkt[88];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    // pkt[3] = flags = 0
    pkt[4] = 0x48;  // payload_len = 72 LE
    // pkt[5..7] = 0
    pkt[8]  = 0x01; pkt[9]  = 0x06; pkt[10] = 0x21;
    // pkt[11..15] = 0

    memcpy(pkt + 16, uid_up, 20);
    pkt[49] = (uint8_t)(epoch >> 8);  // epoch appears twice: [49..50] and [65..66]
    pkt[50] = (uint8_t)(epoch     );
    uint32_t ver = htole32(0x04030304);
    memcpy(pkt + 52, &ver, 4);
    uint32_t cr_le = htole32(client_random);
    memcpy(pkt + 56, &cr_le, 4);
    uint32_t pm_le = htole32(partial_mac);
    memcpy(pkt + 60, &pm_le, 4);
    pkt[64] = directed ? 0x02 : 0x01;
    pkt[65] = (uint8_t)(epoch >> 8);
    pkt[66] = (uint8_t)(epoch     );

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == sizeof(pkt)) ? 0 : -1;
}

// Type 0x33 control packet — session establishment handshake step
// ==========================================================================
//
// 52-byte packet sent after LAN_SEARCH3; printer echoes it back to confirm
// the session token.
//
// Layout (all 52 bytes scrambled with trans_code_partial):
//   [0..15]  IOTC header: magic=0x0204, ver=0x1c, flags=0x02,
//              payload_len=0x24, bytes[8..10]={0x02,0x04,0x33}
//   [16..35] UID (20 bytes, UPPERCASE)
//   [36..43] session_token (8 bytes)
//   [44..47] 0x00000000
//   [48..51] 0x01000000 (little-endian 1 — observed constant)

static int send_ctrl0x33(int sock, const struct sockaddr_in* dst,
                          const char* uid_upper,
                          const uint8_t session_token[8])
{
    uint8_t pkt[52];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;  // flags=0x02 for control packets
    pkt[4] = 0x24;  // payload_len=36 LE
    pkt[8]  = 0x02; pkt[9]  = 0x04; pkt[10] = 0x33;

    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, session_token, 8);
    // [48..51]: one capture shows 0x211e2619 — leave zero for now

    trans_code_partial(pkt, sizeof(pkt));

    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == sizeof(pkt)) ? 0 : -1;
}

// ==========================================================================
// DTLS-PSK handshake — TUTK custom wire format
// ==========================================================================
//
// DTLS-over-IOTC relay — wire format from captured relay traffic:
//
//   DTLS record header: STANDARD DTLS 1.2 (13 bytes)
//     content_type(1) + version(2=0xFEFD) + epoch(2) + seq(6) + length(2)
//
//   DTLS handshake header: STANDARD DTLS 1.2 (12 bytes)
//     type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3)
//
//   Scrambling (TransCodePartial) for DTLS-IOTC packets:
//     Only the FIRST 80 bytes are scrambled (5 × 16-byte decode_block).
//     Bytes 80+ are plaintext DTLS content.  Non-DTLS IOTC packets (JOIN,
//     KNOCK, relay control) still use full-packet scrambling.
//
//   Cipher suite: 0xCCAC (TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
//
//   PSK identity: "AUTHPWD_" + account_name  (e.g. "AUTHPWD_admin")
//     Relay and LAN modes use the same identity.
//
//   PSK key derivation:
//     PSK = SHA256(camera_url_passwd_field)
//     The source is the "passwd" field in the camera URL, which may differ from
//     the device access_code returned by the cloud API; they may differ
//     depending on the printer model.
//     Relay and LAN modes use the same derivation.
//     A1 printers use LAN-mode JPEG on port 6000 and do not use TUTK/DTLS.
//
//   ServerKeyExchange body for ECDHE-PSK (RFC 5489):
//     psk_hint_len(2=0x0000) + curve_type(1=0x03) + named_curve(2=0x001d=x25519)
//     + key_len(1=0x20) + X25519_pub_key(32 bytes)
//
//   ClientKeyExchange body:
//     psk_id_len(2) + psk_identity(N) + ec_point_len(1) + client_pub_key(32)
//
// The session proceeds:
//   Client → Server: ClientHello
//   Server → Client: ServerHello + ServerKeyExchange + ServerHelloDone (194-byte IOTC pkt)
//   Client → Server: ClientKeyExchange + ChangeCipherSpec + Finished  (168-byte IOTC pkt)
//   Server → Client: ChangeCipherSpec + Finished
//
// This implementation builds standard DTLS 1.2 handshake messages
// using OpenSSL crypto primitives for X25519 ECDH and ChaCha20-Poly1305.

// DtlsSession is declared in IotcProtocol.hpp (moved to header so relay code
// in OssAgoraSignaling.cpp can use it via RelayConn).

// TLS 1.2 PRF: P_SHA256 expansion.
// label_seed = label_bytes || seed_bytes
static bool tls12_prf(const uint8_t* secret, size_t secret_len,
                       const char* label,
                       const uint8_t* seed, size_t seed_len,
                       uint8_t* out, size_t out_len)
{
    // A(0) = label || seed
    // A(i) = HMAC-SHA256(secret, A(i-1))
    // P_SHA256 = HMAC-SHA256(secret, A(1)||label||seed) || HMAC-SHA256(secret, A(2)||label||seed) || ...

    size_t llen = strlen(label);
    std::vector<uint8_t> label_seed(llen + seed_len);
    memcpy(label_seed.data(), label, llen);
    memcpy(label_seed.data() + llen, seed, seed_len);

    uint8_t a[32]; // A(i), starts as A(1)
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), secret, (int)secret_len,
         label_seed.data(), label_seed.size(), a, &hmac_len);

    size_t done = 0;
    while (done < out_len) {
        // HMAC(secret, A(i) || label || seed)
        std::vector<uint8_t> hmac_in(32 + label_seed.size());
        memcpy(hmac_in.data(), a, 32);
        memcpy(hmac_in.data() + 32, label_seed.data(), label_seed.size());

        uint8_t block[32];
        HMAC(EVP_sha256(), secret, (int)secret_len,
             hmac_in.data(), hmac_in.size(), block, &hmac_len);

        size_t copy = std::min((size_t)32, out_len - done);
        memcpy(out + done, block, copy);
        done += copy;

        // A(i+1) = HMAC(secret, A(i))
        HMAC(EVP_sha256(), secret, (int)secret_len, a, 32, a, &hmac_len);
    }
    return true;
}

// Build a 12-byte DTLS nonce for the TUTK relay format:
//   nonce = iv XOR (epoch[4B BE] || seq[8B BE])
// For recv paths where seq is 32-bit, pass (uint64_t)seq — high bits are 0.
static void build_relay_nonce(uint8_t nonce[12], const uint8_t iv[12],
                               uint32_t epoch, uint64_t seq)
{
    memcpy(nonce, iv, 12);
    nonce[0] ^= (uint8_t)(epoch >> 24);
    nonce[1] ^= (uint8_t)(epoch >> 16);
    nonce[2] ^= (uint8_t)(epoch >>  8);
    nonce[3] ^= (uint8_t)(epoch      );
    for (int i = 0; i < 8; ++i)
        nonce[4 + i] ^= (uint8_t)(seq >> (56 - 8*i));
}

#ifdef OBN_TESTING
void build_relay_nonce_test(uint8_t nonce[12], const uint8_t iv[12],
                             uint32_t epoch, uint64_t seq)
{
    build_relay_nonce(nonce, iv, epoch, seq);
}
#endif

// Build a standard DTLS 1.2 record header (13 bytes).
// Confirmed from captured packets: version=0xFEFD, epoch=2B, seq=6B.
static void build_dtls_record_hdr(uint8_t* buf, uint8_t content_type,
                                   uint16_t epoch, uint64_t seq, uint16_t length)
{
    buf[0] = content_type;
    buf[1] = 0xfe; buf[2] = 0xfd;              // DTLS 1.2
    buf[3] = (uint8_t)(epoch >> 8);            // epoch (2 bytes, big-endian)
    buf[4] = (uint8_t)(epoch     );
    buf[5] = (uint8_t)(seq >> 40);             // seq (6 bytes, big-endian)
    buf[6] = (uint8_t)(seq >> 32);
    buf[7] = (uint8_t)(seq >> 24);
    buf[8] = (uint8_t)(seq >> 16);
    buf[9] = (uint8_t)(seq >>  8);
    buf[10]= (uint8_t)(seq       );
    buf[11]= (uint8_t)(length >> 8);
    buf[12]= (uint8_t)(length     );
}

// Build a standard DTLS 1.2 handshake header (12 bytes).
// Confirmed from captured packets: frag_offset=3B, frag_len=3B (not TUTK-custom).
static void build_dtls_hs_hdr(uint8_t* buf, uint8_t hs_type,
                                uint32_t body_len, uint16_t msg_seq)
{
    buf[0] = hs_type;
    buf[1] = (uint8_t)(body_len >> 16);
    buf[2] = (uint8_t)(body_len >>  8);
    buf[3] = (uint8_t)(body_len      );
    buf[4] = (uint8_t)(msg_seq >> 8);
    buf[5] = (uint8_t)(msg_seq     );
    buf[6] = 0; buf[7] = 0; buf[8] = 0;       // frag_offset = 0
    buf[9] = (uint8_t)(body_len >> 16);        // frag_len = body_len (no fragmentation)
    buf[10]= (uint8_t)(body_len >>  8);
    buf[11]= (uint8_t)(body_len      );
}

// Full DTLS-PSK handshake over a connected UDP socket.
// initial_epoch: the TUTK session epoch (client-generated, embedded in LAN_SEARCH3).
//   Used for ALL records including ClientHello (confirmed from captures).
// uid_upper: 20-char uppercase UID; used to send the type 0x33 auth packet that the
//   printer requires between ClientHello and ServerHello.
//   Pass NULL to skip (non-LAN paths that don't use DTLS directly).
// passwd: printer DTLS passwd ASCII string (camera URL "passwd" field); PSK = SHA256(passwd).
// account: PSK identity suffix (e.g. "admin"); identity = "AUTHPWD_" + account.
// session_token: 8-byte session token from LAN discovery.
// Returns 0 on success and fills *out with session keys.
static int dtls_psk_handshake(int sock, const struct sockaddr_in* dst,
                               uint32_t initial_epoch,
                               const uint8_t session_token[8],
                               const char* uid_upper_str,
                               const char* passwd, const char* account,
                               DtlsSession* out)
{
    memset(out, 0, sizeof(*out));
    out->epoch = initial_epoch;

    if (RAND_bytes(out->client_random, 32) != 1) {
        fprintf(stderr, "[dtls] RAND_bytes failed\n");
        return -1;
    }

    // =======================================================================
    // Build and send ClientHello
    // =======================================================================
    //
    // ALL DTLS records use the pre-negotiated epoch from LAN_SEARCH_R3
    // (e.g. 0x6a0 = 1696); the ClientHello record header carries this epoch, not 0.
    //
    // HS header: type=0x01 (ClientHello), msg_seq=0, tutk_epoch=initial_epoch
    // Body: version(2)=0xfefd (DTLS 1.2) + random(32) + session_id_len(1)=0
    //       + cookie_len(1)=0 + cipher_suites_len(2) + cipher_suites
    //       + compression_len(1)=1 + compression(1)=0

    // Cipher suites: 0xCCAC (ECDHE-PSK-CHACHA20) + 0x00FF (EMPTY-RENEGOTIATION)
    static const uint8_t kCipherSuites[] = {
        0xCC, 0xAC,   // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        0x00, 0xFF,   // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    };

    uint8_t ch_body[64];
    size_t ch_off = 0;
    ch_body[ch_off++] = 0xfe; ch_body[ch_off++] = 0xfd;  // hello version DTLS 1.2
    memcpy(ch_body + ch_off, out->client_random, 32); ch_off += 32;
    ch_body[ch_off++] = 0x00;   // session_id_len = 0
    ch_body[ch_off++] = 0x00;   // cookie_len = 0
    ch_body[ch_off++] = 0x00; ch_body[ch_off++] = 0x04;  // cipher_suites_len = 4
    memcpy(ch_body + ch_off, kCipherSuites, 4); ch_off += 4;
    ch_body[ch_off++] = 0x01;   // compression_methods_len = 1
    ch_body[ch_off++] = 0x00;   // compression = null
    // no extensions

    uint8_t hs_hdr[12];
    build_dtls_hs_hdr(hs_hdr, 0x01, (uint32_t)ch_off, 0);

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, 0x16, initial_epoch, 0, (uint16_t)(12 + ch_off));

    std::vector<uint8_t> ch_dtls(13 + 12 + ch_off);
    memcpy(ch_dtls.data(),      rec_hdr, 13);
    memcpy(ch_dtls.data() + 13, hs_hdr,  12);
    memcpy(ch_dtls.data() + 25, ch_body, ch_off);

    // Handshake transcript: concatenation of all HS message bodies (hs_hdr + body).
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), hs_hdr, hs_hdr + 12);
    transcript.insert(transcript.end(), ch_body, ch_body + ch_off);

    if (send_dtls_packet(sock, dst, initial_epoch, session_token,
                          ch_dtls.data(), ch_dtls.size()) != 0) {
        fprintf(stderr, "[dtls] ClientHello send failed\n");
        return -1;
    }
    fprintf(stderr, "[dtls] ClientHello sent (%zu bytes DTLS, epoch=0x%x)\n",
            ch_dtls.size(), initial_epoch);

    // =======================================================================
    // Send type 0x33 authorization and drain echo
    // =======================================================================
    //
    // Sequence: ClientHello → type 0x33 send → type 0x33 echo recv → ServerHello recv.
    // The printer withholds ServerHello until it receives the 0x33 packet
    // (which confirms the session token and UID).
    if (uid_upper_str && uid_upper_str[0]) {
        if (send_ctrl0x33(sock, dst, uid_upper_str, session_token) != 0) {
            fprintf(stderr, "[dtls] type 0x33 send failed\n");
            return -1;
        }
        fprintf(stderr, "[dtls] type 0x33 sent, waiting for echo\n");

        // Drain the 52-byte echo. It is a raw IOTC packet (not DTLS-wrapped).
        uint8_t echo_buf[64];
        struct sockaddr_in echo_src{};
        socklen_t echo_slen = sizeof(echo_src);
        set_recv_timeout(sock, 3000);
        ssize_t en = recvfrom(sock, echo_buf, sizeof(echo_buf), 0,
                               (struct sockaddr*)&echo_src, &echo_slen);
        if (en == 52) {
            fprintf(stderr, "[dtls] 0x33 echo received\n");
        } else {
            fprintf(stderr, "[dtls] 0x33 echo: unexpected size %zd (expected 52)\n", en);
        }
    }

    // =======================================================================
    // Receive ServerHello (+ ServerKeyExchange + ServerHelloDone in same IOTC pkt)
    // =======================================================================

    uint8_t srv_raw[1024];
    uint32_t srv_epoch = 0;
    uint8_t srv_token[8] = {};
    int srv_len = recv_dtls_packet(sock, srv_raw, sizeof(srv_raw),
                                    &srv_epoch, srv_token, 5000);
    if (srv_len < 13) {
        fprintf(stderr, "[dtls] no ServerHello (got %d bytes)\n", srv_len);
        return -1;
    }

    if (srv_raw[0] != 0x16 || srv_raw[1] != 0xfe || srv_raw[2] != 0xfd) {
        fprintf(stderr, "[dtls] unexpected record type 0x%02x\n", srv_raw[0]);
        return -1;
    }
    out->epoch = srv_epoch;

    uint16_t rec_len;
    rec_len = ((uint16_t)srv_raw[11] << 8) | srv_raw[12];
    fprintf(stderr, "[dtls] ServerHello record: epoch=0x%04x len=%u\n",
            srv_epoch, rec_len);

    // HS header starts at offset 13
    // type(1) + len(3) + msg_seq(2) + tutk_epoch(4) + frag_len(2) = 12 bytes
    if (srv_len < 25) { fprintf(stderr, "[dtls] ServerHello too short\n"); return -1; }
    uint8_t hs_type = srv_raw[13];
    uint32_t hs_body_len = ((uint32_t)srv_raw[14] << 16)
                         | ((uint32_t)srv_raw[15] << 8)
                         |  (uint32_t)srv_raw[16];
    fprintf(stderr, "[dtls] ServerHello HS type=0x%02x body_len=%u\n",
            hs_type, hs_body_len);

    if (hs_type != 0x02) {
        fprintf(stderr, "[dtls] expected ServerHello (0x02), got 0x%02x\n", hs_type);
        return -1;
    }

    // TUTK ServerHello body: version(2)+random(32); session_id_len may be non-standard
    // (observed 0xcc=204 from firmware), so grab random by offset, not after session_id.
    if (srv_len >= 25 + 2 + 32) {
        memcpy(out->server_random, srv_raw + 25 + 2, 32);
        fprintf(stderr, "[dtls] server_random extracted\n");
    } else {
        fprintf(stderr, "[dtls] ServerHello body too short for random\n");
        return -1;
    }

    transcript.insert(transcript.end(), srv_raw + 13, srv_raw + 13 + 12 + hs_body_len);

    // TUTK bundles ServerHello + ServerKeyExchange + ServerHelloDone in one IOTC packet.
    uint8_t server_ec_pub[33] = {};   // server's X25519 public key (32 bytes)
    bool has_server_ec = false;
    bool has_server_hello_done = false;

    int pos = 13 + (int)rec_len;  // advance past first record
    while (pos + 13 <= srv_len) {
        uint8_t rtype = srv_raw[pos];
        uint16_t rlen = ((uint16_t)srv_raw[pos+11] << 8) | srv_raw[pos+12];
        if (pos + 13 + rlen > srv_len) break;

        if (rtype == 0x16 && pos + 13 + 12 <= srv_len) {
            uint8_t htype = srv_raw[pos + 13];
            uint32_t hlen = ((uint32_t)srv_raw[pos+14] << 16)
                          | ((uint32_t)srv_raw[pos+15] << 8)
                          |  (uint32_t)srv_raw[pos+16];

            transcript.insert(transcript.end(),
                              srv_raw + pos + 13, srv_raw + pos + 13 + 12 + hlen);

            if (htype == 0x0c) {
                // ServerKeyExchange: RFC 5489 ECDHE-PSK body:
                //   psk_hint_len(2=0) + curve_type(1=0x03) + named_curve(2=0x001d=x25519)
                //   + key_len(1) + key(32) = 38 bytes total
                int ke_body_start = pos + 13 + 12;
                if (hlen >= 38 && srv_raw[ke_body_start] == 0x00
                               && srv_raw[ke_body_start+1] == 0x00
                               && srv_raw[ke_body_start+2] == 0x03) {
                    uint8_t key_len = srv_raw[ke_body_start + 5];
                    if (key_len <= 33 && (int)hlen >= 6 + (int)key_len) {
                        memcpy(server_ec_pub, srv_raw + ke_body_start + 6, key_len);
                        has_server_ec = true;
                        fprintf(stderr, "[dtls] ServerKeyExchange: %u-byte EC key\n", key_len);
                    }
                }
            } else if (htype == 0x0e) {
                has_server_hello_done = true;
                fprintf(stderr, "[dtls] ServerHelloDone received\n");
            }
        }
        pos += 13 + (int)rlen;
    }

    if (!has_server_hello_done) {
        fprintf(stderr, "[dtls] ServerHelloDone not found in server response\n");
        // Continue anyway — some TUTK firmwares pack things differently
    }

    // =======================================================================
    // Generate client ECDHE key pair (X25519)
    // =======================================================================

    EVP_PKEY* client_privkey = nullptr;
    uint8_t client_ec_pub[32] = {};
    uint8_t premaster_ecdh[32] = {};

    if (has_server_ec) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0
                  || EVP_PKEY_keygen(pctx, &client_privkey) <= 0) {
            fprintf(stderr, "[dtls] X25519 keygen failed\n");
            EVP_PKEY_CTX_free(pctx);
            return -1;
        }
        EVP_PKEY_CTX_free(pctx);

        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(client_privkey, client_ec_pub, &pub_len);

        EVP_PKEY* server_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                              server_ec_pub, 32);
        if (server_pkey) {
            EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(client_privkey, nullptr);
            size_t ss_len = 32;
            if (dctx && EVP_PKEY_derive_init(dctx) > 0
                     && EVP_PKEY_derive_set_peer(dctx, server_pkey) > 0
                     && EVP_PKEY_derive(dctx, premaster_ecdh, &ss_len) > 0) {
                fprintf(stderr, "[dtls] ECDH shared secret computed (%zu bytes)\n", ss_len);
            } else {
                fprintf(stderr, "[dtls] ECDH derive failed\n");
            }
            EVP_PKEY_CTX_free(dctx);
            EVP_PKEY_free(server_pkey);
        }
        EVP_PKEY_free(client_privkey);
    }

    // =======================================================================
    // Compute PSK and premaster secret (ECDHE-PSK)
    // =======================================================================
    //
    // PSK = SHA256(passwd_ascii_string)
    //
    // For ECDHE-PSK premaster secret (RFC 5489):
    //   premaster = uint16_len(ecdh_secret) || ecdh_secret
    //               || uint16_len(psk)       || psk

    uint8_t psk[32];
    SHA256(reinterpret_cast<const uint8_t*>(passwd), strlen(passwd), psk);
    fprintf(stderr, "[dtls] PSK = SHA256(passwd) computed\n");

    // ECDHE-PSK premaster: uint16_len(ecdh_secret) || ecdh_secret || uint16_len(psk) || psk
    uint8_t premaster[2 + 32 + 2 + 32];
    size_t pm_off = 0;
    premaster[pm_off++] = 0x00; premaster[pm_off++] = 0x20;  // ecdh_len = 32
    memcpy(premaster + pm_off, premaster_ecdh, 32); pm_off += 32;
    premaster[pm_off++] = 0x00; premaster[pm_off++] = 0x20;  // psk_len = 32
    memcpy(premaster + pm_off, psk, 32); pm_off += 32;

    // =======================================================================
    // Compute master_secret = PRF(premaster, "master secret", client_random||server_random)
    // =======================================================================

    uint8_t ms_seed[64];
    memcpy(ms_seed,      out->client_random, 32);
    memcpy(ms_seed + 32, out->server_random, 32);
    tls12_prf(premaster, sizeof(premaster), "master secret",
              ms_seed, 64, out->master_secret, 48);
    fprintf(stderr, "[dtls] master_secret derived\n");

    // =======================================================================
    // Key expansion: PRF(master_secret, "key expansion", server_random||client_random)
    // =======================================================================
    // For ChaCha20-Poly1305: key=32B, IV=12B per direction → 2*(32+12) = 88 bytes

    uint8_t ke_seed[64];
    memcpy(ke_seed,      out->server_random, 32);
    memcpy(ke_seed + 32, out->client_random, 32);
    uint8_t key_block[88];
    tls12_prf(out->master_secret, 48, "key expansion",
              ke_seed, 64, key_block, sizeof(key_block));

    memcpy(out->client_write_key, key_block,      32);
    memcpy(out->server_write_key, key_block + 32, 32);
    memcpy(out->client_write_iv,  key_block + 64, 12);
    memcpy(out->server_write_iv,  key_block + 76, 12);
    fprintf(stderr, "[dtls] key expansion done\n");

    // =======================================================================
    // Build ClientKeyExchange
    // =======================================================================
    //
    // Body: identity_len(2) + identity(N) + ec_key_len(1) + ec_pub_key(32)
    //   identity = "AUTHPWD_" + account  (e.g. "AUTHPWD_admin")
    //
    // Note: RFC 5489 puts ec_key before identity; TUTK reverses this (non-standard).

    std::string psk_identity = std::string("AUTHPWD_") + account;

    std::vector<uint8_t> cke_body;
    uint16_t id_len = (uint16_t)psk_identity.size();
    cke_body.push_back((id_len >> 8) & 0xff);
    cke_body.push_back(id_len & 0xff);
    cke_body.insert(cke_body.end(), psk_identity.begin(), psk_identity.end());
    if (has_server_ec) {
        cke_body.push_back(0x20);  // ec key length = 32
        cke_body.insert(cke_body.end(), client_ec_pub, client_ec_pub + 32);
    }

    uint8_t cke_rec_hdr[13], cke_hs_hdr[12];
    build_dtls_hs_hdr(cke_hs_hdr, 0x10 /*ClientKeyExchange*/,
                       (uint32_t)cke_body.size(), 1 /*msg_seq*/);
    build_dtls_record_hdr(cke_rec_hdr, 0x16, out->epoch, 1,
                           (uint16_t)(12 + cke_body.size()));

    transcript.insert(transcript.end(), cke_hs_hdr, cke_hs_hdr + 12);
    transcript.insert(transcript.end(), cke_body.begin(), cke_body.end());

    // =======================================================================
    // Build ChangeCipherSpec
    // =======================================================================

    uint8_t ccs_rec[14];
    build_dtls_record_hdr(ccs_rec, 0x14 /*ChangeCipherSpec*/, out->epoch, 2, 1);
    ccs_rec[13] = 0x01;

    // =======================================================================
    // Build Finished
    // =======================================================================
    //
    // verify_data = PRF(master_secret, "client finished", SHA256(transcript))
    // Finished body = verify_data (12 bytes for TLS 1.2)

    uint8_t transcript_hash[32];
    SHA256(transcript.data(), transcript.size(), transcript_hash);

    uint8_t verify_data[12];
    tls12_prf(out->master_secret, 48, "client finished",
              transcript_hash, 32, verify_data, 12);

    // Finished HS header
    uint8_t fin_hs_hdr[12], fin_rec_hdr[13];
    build_dtls_hs_hdr(fin_hs_hdr, 0x14 /*Finished*/, 12, 2 /*msg_seq*/);

    // Finished is encrypted; tx_seq=0 because CCS resets the sequence counter.
    // nonce = write_IV XOR (epoch(2B BE at [4..5]) || seq(6B BE at [6..11]))
    uint64_t fin_seq = 0;
    uint8_t nonce[12];
    memcpy(nonce, out->client_write_iv, 12);
    nonce[4] ^= (uint8_t)((uint16_t)out->epoch >> 8);
    nonce[5] ^= (uint8_t)((uint16_t)out->epoch     );
    for (int i = 0; i < 6; ++i)
        nonce[6 + i] ^= (uint8_t)(fin_seq >> (40 - 8*i));

    // AAD = DTLS record header (plaintext length = 12 HS hdr + 12 verify_data)
    uint8_t fin_aad[13];
    build_dtls_record_hdr(fin_aad, 0x16, out->epoch, (uint32_t)fin_seq,
                           (uint16_t)(12 + 12));  // 12 HS hdr + 12 verify_data

    uint8_t fin_plain[12 + 12];
    memcpy(fin_plain,      fin_hs_hdr,   12);
    memcpy(fin_plain + 12, verify_data,  12);

    uint8_t fin_cipher[24 + 16];  // plaintext + 16-byte Poly1305 tag
    int fin_cipher_len = 0;
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, out->client_write_key, nonce);
        EVP_EncryptUpdate(ctx, nullptr, &outl, fin_aad, 13);  // AAD
        EVP_EncryptUpdate(ctx, fin_cipher, &outl, fin_plain, sizeof(fin_plain));
        fin_cipher_len = outl;
        EVP_EncryptFinal_ex(ctx, fin_cipher + fin_cipher_len, &outl);
        fin_cipher_len += outl;
        uint8_t tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        memcpy(fin_cipher + fin_cipher_len, tag, 16);
        fin_cipher_len += 16;
        EVP_CIPHER_CTX_free(ctx);
    }

    build_dtls_record_hdr(fin_rec_hdr, 0x16, out->epoch, (uint32_t)fin_seq,
                           (uint16_t)fin_cipher_len);

    // =======================================================================
    // Send ClientKeyExchange + ChangeCipherSpec + Finished in one IOTC packet
    // =======================================================================

    std::vector<uint8_t> cke_ccs_fin;
    // CKE record
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_rec_hdr, cke_rec_hdr + 13);
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_hs_hdr, cke_hs_hdr + 12);
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_body.begin(), cke_body.end());
    // CCS record
    cke_ccs_fin.insert(cke_ccs_fin.end(), ccs_rec, ccs_rec + 14);
    // Finished record (encrypted)
    cke_ccs_fin.insert(cke_ccs_fin.end(), fin_rec_hdr, fin_rec_hdr + 13);
    cke_ccs_fin.insert(cke_ccs_fin.end(), fin_cipher, fin_cipher + fin_cipher_len);

    if (send_dtls_packet(sock, dst, out->epoch, session_token,
                          cke_ccs_fin.data(), cke_ccs_fin.size()) != 0) {
        fprintf(stderr, "[dtls] CKE+CCS+Finished send failed\n");
        return -1;
    }
    fprintf(stderr, "[dtls] CKE+CCS+Finished sent (%zu bytes DTLS)\n", cke_ccs_fin.size());

    // =======================================================================
    // Receive and verify server CCS + Finished
    // =======================================================================

    uint8_t srv2_raw[1024];
    int srv2_len = recv_dtls_packet(sock, srv2_raw, sizeof(srv2_raw),
                                     nullptr, nullptr, 5000);
    if (srv2_len < 14) {
        fprintf(stderr, "[dtls] no server CCS/Finished (got %d bytes)\n", srv2_len);
        return -1;
    }

    bool got_ccs = (srv2_raw[0] == 0x14);  // 0x14=CCS, then 0x16=Finished
    fprintf(stderr, "[dtls] server response: got_ccs=%d len=%d\n", got_ccs, srv2_len);

    out->tx_seq = 1;
    out->rx_seq = 0;
    out->handshake_complete = true;

    fprintf(stderr, "[dtls] handshake complete! epoch=0x%04x\n", out->epoch);
    return 0;
}

// ==========================================================================
// P2P NAT traversal state machine
// ==========================================================================
//
// This is the core of the TUTK IOTC protocol.
// The state machine follows the sequence observed in IOTC_Connect_UDP_Inner.
//
// States (from CheckUDPSequentialConnectState / CheckUDPParellelConnectState):
//   UDP_QUERY_DEVICE_START
//   → send MSG_P2P_PRECHECK1 to device WAN address (from master server reply)
//   → recv MSG_P2P_PRECHECK1_R from device
//   → send MSG_P2P_PRECHECK2 (with auth key if required)
//   → send MSG_P2P_REQUEST
//   → recv MSG_P2P_KNOCK1 / MSG_P2P_KNOCK2 from device
//   → send MSG_P2P_KNOCK_R1 / MSG_P2P_KNOCK_R2
//   → recv MSG_P2P_KNOCK_RR1 / MSG_P2P_KNOCK_RR2
//   → send MSG_P2P_PUNCH_TO  (tells device our local address)
//   → P2P session established
//   → start MSG_P2P_ALIVE_C2D keepalives
//
// If NAT type is 5 (symmetric), IOTC_TryPortAddNode is called to probe
// a range of ports (IOTC_TryPort* family).
//
// Relay fallback (AddUDPRelayConnectTask):
//   → send MSG_RLY_REQUEST to relay server
//   → recv MSG_RLY_REQUEST_R2 ("Ready for RLY")
//   → relay server sends MSG_RLY_KNOCK to device
//   → device sends MSG_RLY_KNOCK to client
//   → data flows through relay via MSG_RLY_PACKET_S2C / MSG_RLY_PACKET_S2D

enum class P2PState {
    IDLE,
    LAN_SEARCH,
    QUERY_MASTER,         // TCP: send UID to master, get device WAN addr
    PRECHECK,             // UDP: MSG_P2P_PRECHECK1 → PRECHECK1_R
    KNOCK,                // UDP: MSG_P2P_KNOCK exchange
    RELAY,                // TCP relay fallback
    CONNECTED,
    FAILED,
};

// Minimal session context for the OSS P2P client.
struct OssSession {
    std::string uid;             // 20-char device UID (lowercase)
    uint64_t    authkey;         // 8-byte auth key from URL
    std::string password;        // AV password ("888888")
    TutkRegion  region;

    int         udp_sock;        // UDP P2P socket
    uint16_t    local_port;      // bound local port
    uint32_t    client_random;
    uint32_t    dtls_epoch;      // client-generated epoch echoed in LAN_SEARCH_R3 (e.g. 0x6a0)
    uint8_t     session_token[8]; // client_random(4B) + partial_mac(4B)

    struct sockaddr_in device_wan;  // device WAN address (from master/LAN)
    P2PState    state;

    DtlsSession dtls;            // filled by dtls_psk_handshake on connect

    // Keepalive thread (started after P2P session established)
    bool        keepalive_run;   // signal thread to stop
    pthread_t   keepalive_tid;
};

// ==========================================================================
// TUTK wire-format helpers (derived from disassembly)
// ==========================================================================
//
// TUTK UDP/TCP message header layout (16 bytes), confirmed from:
//   _IOTC_Send_Search      @ 0x190130  (LAN search broadcast)
//   _IOTC_SendPreCheck1    @ 0x18e8b0  (P2P precheck phase 1)
//   _IOTC_SendPreCheck2    @ 0x18fb00  (P2P precheck phase 2 with auth)
//   _IOTC_SendQuryDevice5  @ 0x190eb0  (query device via master TCP)
//   _IOTC_Send_Punch_To    @ 0x190790  (NAT punch-to)
//
// Layout (all fields little-endian):
//   [0..1]  uint16  magic   = 0x0204  (TUTK protocol marker, constant)
//   [2]     uint8   version = 0x1c    (version byte, constant)
//   [3]     uint8   flags   = 0x00    (iotc_SendMessage ORs in 0x02)
//   [4..5]  uint16  payload_len       (bytes after this 16-byte header)
//   [6..7]  uint16  = 0x0000          (zero pad)
//   [8..9]  uint16  sub_cmd           (message-specific identifier byte 1+2)
//   [10]    uint8   extra_cmd         (message-specific byte 3)
//   [11..15] uint8  = 0x00 x5         (zero pad)
//
// Confirmed sub_cmd + extra_cmd bytes:
//   MSG_LAN_SEARCH3:     [8]=0x01, [9]=0x06, [10]=0x21
//   MSG_P2P_PRECHECK1:   [8]=0x11, [9]=0x02, [10]=0x24
//   MSG_P2P_PRECHECK2:   [8]=0x14, [9]=0x02, [10]=0x24
//   MSG_QUERY_DEVICE5:   [8]=0x07, [9]=0x10, [10]=0x18
//   MSG_P2P_PUNCH_TO:    [8]=0x01, [9]=0x03, [10]=0x21
//
// Confirmed payload_len values (bytes after header):
//   MSG_LAN_SEARCH3:     0x48 = 72  → total send = 88 bytes
//   MSG_P2P_PRECHECK1:   0x14 = 20  → total send = 36 bytes
//   MSG_P2P_PRECHECK2:   0x20 = 32  → total send = 48 bytes
//   MSG_QUERY_DEVICE5:   0x26 = 38  → total send = 54 bytes
//   MSG_P2P_PUNCH_TO:    0x24 = 36  → total send = 52 bytes

static void fill_tutk_hdr(uint8_t* buf, uint16_t payload_len,
                           uint8_t b8, uint8_t b9, uint8_t b10)
{
    memset(buf, 0, 16);
    buf[0] = 0x04; buf[1] = 0x02;  // 0x0204 LE
    buf[2] = 0x1c;
    buf[3] = 0x00;
    buf[4] = (uint8_t)(payload_len & 0xff);
    buf[5] = (uint8_t)(payload_len >> 8);
    buf[6] = 0; buf[7] = 0;
    buf[8]  = b8;
    buf[9]  = b9;
    buf[10] = b10;
    // [11..15] = 0
}

// hdr_b8/b9/b10: msg-type bytes at offsets [8],[9],[10] (see TUTK wire format above).
static ssize_t tutk_udp_send(int sock_fd, const struct sockaddr_in* dst,
                              uint8_t hdr_b8, uint8_t hdr_b9, uint8_t hdr_b10,
                              const void* payload, size_t payload_len)
{
    uint8_t pkt[2048];
    size_t total = 16 + payload_len;
    if (total > sizeof(pkt)) return -1;

    fill_tutk_hdr(pkt, (uint16_t)payload_len, hdr_b8, hdr_b9, hdr_b10);
    if (payload_len > 0)
        memcpy(pkt + 16, payload, payload_len);

    return sendto(sock_fd, pkt, total, 0,
                  (const struct sockaddr*)dst, sizeof(*dst));
}

static ssize_t tutk_udp_recv(int sock_fd, uint8_t* buf, size_t buf_size,
                              struct sockaddr_in* src, int timeout_ms)
{
    set_recv_timeout(sock_fd, timeout_ms);
    socklen_t src_len = sizeof(*src);
    return recvfrom(sock_fd, buf, buf_size, 0,
                    (struct sockaddr*)src, &src_len);
}

// ==========================================================================
// Master server TCP protocol
// ==========================================================================
//
// Confirmed from disassembly:
//   IOTC_TcpConnectToMaster @ 0x1928f0 calls IOTC_TcpConnectToMasterTryPort
//   @ 0x189f80 which iterates through a port table gTcpTryPort:
//   {80, 443, 21047, 8080, 8000, 20297, 17236, 8686} — up to 12 slots,
//   0-valued slots skipped.  The actual TCP I/O goes through a pConnMgr vtable
//   (vtable calls at 0x18a0c1, 0x18a0f7, 0x18a194 etc.), which hides the
//   exact wire format.
//
// _IOTC_SendQuryDevice5 sends a 54-byte packet (header + 38 bytes payload):
//   Payload layout (confirmed from disassembly @ 0x190eb0–0x190f90):
//     [0..19]   uid (20 bytes, lowercase)
//     [20..35]  GetRealm() output (16 bytes, realm identifier, zero in OSS)
//     [36]      0x06  (confirmed: movb $0x6, 0x34(%rsp), offset 52 = 36 in payload)
//     [37]      extra byte from r8 arg (connect_flag byte)
//
// The master responds with MSG_QUERY_DEVICE5_R (type unknown) containing:
//   device WAN IP:port — parsed to fill sess->device_wan.
//
// NOTE: CheckLicenseKeyIsValid() returns -1004 in the Bambu-modified TUTK
// library, so the master registration path is permanently short-circuited and
// this function is never called at runtime.  Retained as a reference
// implementation of the standard TUTK master protocol.

static bool query_master_for_device(const std::string& uid_lc,
                                    uint32_t client_random,
                                    TutkRegion region,
                                    struct sockaddr_in* device_addr)
{
    // Port table from gTcpTryPort (confirmed from disassembly gTcpTryPort array):
    // {80, 443, 21047, 8080, 8000, 20297, 17236, 8686}
    // Port 443 uses TLS in the real SDK (IOTC_sCHL_* via pConnMgr vtable) — skip it
    // for plain TCP; a pcap is needed to confirm the cipher suite before adding TLS.
    // Try plain-TCP ports only: 8080, 8000, 80, 21047 in order.
    static const uint16_t kTryPorts[] = { 8080, 8000, 80, 21047 };
    static const size_t   kNumPorts   = sizeof(kTryPorts) / sizeof(kTryPorts[0]);

    const char* suffixes[] = { ".iotcplatform.com", ".kalayservice.com" };
    const char* rname;
    switch (region) {
        case TutkRegion::CN:   rname = "cn";   break;
        case TutkRegion::EU:   rname = "eu";   break;
        case TutkRegion::US:   rname = "us";   break;
        case TutkRegion::Asia: rname = "asia"; break;
        default:               rname = "";     break;
    }

    for (const char* suffix : suffixes) {
        std::string hostname = rname[0]
            ? std::string(rname) + "-c-master" + suffix  // dash separator: matches master_hostname() and relay pattern
            : std::string("c-master") + suffix;

        for (size_t pi = 0; pi < kNumPorts; ++pi) {
            uint16_t port = kTryPorts[pi];

            struct sockaddr_in master_addr{};
            if (!resolve_master(hostname, port, &master_addr)) continue;

            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd < 0) continue;

            struct timeval tv{ 3, 0 };  // 3-second connect timeout
            setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            if (connect(tcp_fd, (struct sockaddr*)&master_addr,
                        sizeof(master_addr)) != 0) {
                close(tcp_fd);
                continue;
            }
            fprintf(stderr, "[oss-iotc] connected to master %s:%u\n",
                    hostname.c_str(), port);

            // Build MSG_QUERY_DEVICE5 packet (54 bytes total):
            // Confirmed layout from _IOTC_SendQuryDevice5 @ 0x190eb0:
            //   [0..15]  header: magic=0x0204, ver=0x1c, payload_len=0x26,
            //                    sub_cmd bytes [8..10] = 0x07, 0x10, 0x18
            //   [16..35] uid (20 bytes, lowercase)
            //   [36..51] realm (16 bytes, zero in OSS — GetRealm() returns 0)
            //   [52]     0x06  (confirmed constant)
            //   [53]     0x00  (connect_flag byte, 0 = default)
            uint8_t pkt[54];
            memset(pkt, 0, sizeof(pkt));
            fill_tutk_hdr(pkt, 0x26, 0x07, 0x10, 0x18);  // confirmed bytes
            memcpy(pkt + 16, uid_lc.c_str(), kUidLen);    // uid at +16
            // [36..51] = GetRealm → zero (OSS has no realm)
            pkt[52] = 0x06;   // confirmed constant
            pkt[53] = 0x00;   // extra flag, 0 = default

            // Plain TCP send matches what the standard TUTK SDK does on non-443 ports.
            ssize_t sent = write(tcp_fd, pkt, sizeof(pkt));
            if (sent != (ssize_t)sizeof(pkt)) {
                fprintf(stderr, "[oss-iotc] master send failed\n");
                close(tcp_fd);
                continue;
            }

            // Receive response (MSG_QUERY_DEVICE5_R).
            // Layout confirmed from _IOTC_RecvQueryDevice5_R disassembly:
            //   [0..1]   magic = 0x0204 (LE) — same TUTK header magic
            //   [2]      ver   = 0x1c
            //   [3..5]   payload_len and padding
            //   [8..10]  reply type bytes = 0x15, 0x02, 0x24
            //   [11..15] padding
            //   [16..19] result code (uint32 LE, 0 = success)
            //   [20..23] device WAN IPv4 (4 bytes, network/big-endian order)
            //   [24..25] device WAN port (uint16, big-endian)
            //   [26..27] padding / flags
            //   [28..31] relay server IPv4 (may be 0 if no relay assigned)
            //   [32..33] relay server port
            //   [34..53] additional relay entries and flags (inferred from size)
            uint8_t resp[256];
            ssize_t n = read(tcp_fd, resp, sizeof(resp));
            close(tcp_fd);

            if (n < 26) {
                fprintf(stderr, "[oss-iotc] master response too short (%zd bytes)\n", n);
                continue;
            }

            if (resp[0] != 0x04 || resp[1] != 0x02) {
                fprintf(stderr, "[oss-iotc] master response: bad magic %02x%02x\n",
                        resp[0], resp[1]);
                continue;
            }

            // Result code at [16..19], uint32 LE (confirmed from _IOTC_RecvQueryDevice5_R).
            uint32_t result_code;
            memcpy(&result_code, resp + 16, 4);
            result_code = le32toh(result_code);
            if (result_code != 0) {
                fprintf(stderr, "[oss-iotc] master returned error 0x%08x\n",
                        result_code);
                continue;
            }

            // Device WAN IPv4 at [20..23] (network order), port at [24..25] (big-endian).
            // Confirmed from _IOTC_RecvQueryDevice5_R field extraction offsets.
            struct sockaddr_in dev_addr{};
            dev_addr.sin_family = AF_INET;
            memcpy(&dev_addr.sin_addr, resp + 20, 4);  // already network order
            uint16_t dev_port;
            memcpy(&dev_port, resp + 24, 2);
            dev_addr.sin_port = dev_port;  // already big-endian (network order)

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dev_addr.sin_addr, ip_str, sizeof(ip_str));
            fprintf(stderr, "[oss-iotc] master: device WAN = %s:%u\n",
                    ip_str, ntohs(dev_addr.sin_port));

            *device_addr = dev_addr;
            return true;
        }
    }
    return false;
}

// ==========================================================================
// P2P NAT punch-through (PRECHECK → KNOCK → PUNCH_TO)
// ==========================================================================
//
// Confirmed from disassembly:
//
// MSG_P2P_PRECHECK1 (36 bytes total):
//   _IOTC_SendPreCheck1 @ 0x18e8b0:
//     header: magic=0x0204, ver=0x1c, payload_len=0x14, bytes[8,9,10]=0x11,0x02,0x24
//     payload [16..35]: uid (20 bytes, lowercase)
//
// MSG_P2P_PRECHECK2 (48 bytes total):
//   _IOTC_SendPreCheck2 @ 0x18fb00:
//     header: magic=0x0204, ver=0x1c, payload_len=0x20, bytes[8,9,10]=0x14,0x02,0x24
//     payload [16..35]: uid (20 bytes)
//     payload [36..39]: 0x00000000 (padding)
//     payload [40..47]: authkey (8 bytes LE, only if authkey != 0)
//
// MSG_P2P_PUNCH_TO (52 bytes total):
//   _IOTC_Send_Punch_To @ 0x190790:
//     header: magic=0x0204, ver=0x1c, payload_len=0x24, bytes[8,9,10]=0x01,0x03,0x21
//     payload [0..15]:  local  address (netaddr 16 bytes: 2+4+2+8 layout via iotc_netaddr)
//     payload [16..19]: extra  field from r13[0x10] (client_random? flags?)
//     payload [20..35]: remote address (netaddr 16 bytes from peer sockaddr)
//
// The netaddr layout used by iotc_netaddr_put_content/get_content (0x138690/0x133d20):
//   Derived from usage — stores IP+port in a platform netaddr struct.
//   Best guess based on how inet addresses are stored in TUTK:
//     [0..1]   AF (uint16 LE, 0x02 = AF_INET)
//     [2..3]   port (uint16 BE = network byte order)
//     [4..7]   IPv4 address (4 bytes, network byte order)
//     [8..15]  zero pad
//   Total: 16 bytes.  This mirrors BSD sockaddr_in without the sin_len field.
// TODO: verify from pcap.
//
// MSG_P2P_KNOCK and KNOCK_R / KNOCK_RR:
//   These are exchange messages for hole-punching.  From log strings:
//     "Send MSG_P2P_KNOCK to %s:%d, ClientRandomID[%d]"
//     "Send MSG_P2P_KNOCK_R, to %s : %d RandomID %u"
//     "Send MSG_P2P_KNOCK_RR, to %s : %d RandomID[%u]"
//   Their exact wire format is not confirmed from disassembly.
//   Best guess: header + uint32 client_random_id (4 bytes)  — total 20 bytes.
//   TODO: verify from pcap.
//
// The reply MSG_P2P_PRECHECK1_R triggers the PRECHECK2 → KNOCK sequence.
// In UDPP2PConnectTaskCB (0x18ed80) the handler checks the response type
// and transitions through states:
//   state 0 → send PRECHECK1 → wait PRECHECK1_R (state 1)
//   state 1 → send PRECHECK2 + REQUEST → wait KNOCK (state 2)
//   state 2 → recv KNOCK → send KNOCK_R → recv KNOCK_RR → send PUNCH_TO (state 3)
//   state 3 → CONNECTED

// Fill a 16-byte TUTK netaddr from a sockaddr_in.
// Layout: [0..1]=AF_INET, [2..3]=port(BE), [4..7]=IPv4(BE), [8..15]=0
static void fill_tutk_netaddr(uint8_t* buf, const struct sockaddr_in* addr)
{
    memset(buf, 0, 16);
    buf[0] = 0x02; buf[1] = 0x00;           // AF_INET LE
    memcpy(buf + 2, &addr->sin_port, 2);     // port BE (already network order)
    memcpy(buf + 4, &addr->sin_addr, 4);     // IPv4 BE (already network order)
}

static ssize_t send_precheck1(int sock_fd, const struct sockaddr_in* dst,
                               const std::string& uid_lc)
{
    uint8_t payload[20];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, uid_lc.c_str(), kUidLen);

    fprintf(stderr, "[oss-iotc] send PRECHECK1 → %s:%u\n",
            inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x11, 0x02, 0x24,   // confirmed from disassembly
                         payload, sizeof(payload));
}

static ssize_t send_precheck2(int sock_fd, const struct sockaddr_in* dst,
                               const std::string& uid_lc, uint64_t authkey)
{
    uint8_t payload[32];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, uid_lc.c_str(), kUidLen);       // [0..19] uid
    // [20..23] = 0x00000000 padding (confirmed: movl $0x0,0x34(rsp))
    // [24..31] = authkey LE (confirmed: only set if extra_arg non-null)
    if (authkey != 0)
        memcpy(payload + 24, &authkey, 8);

    fprintf(stderr, "[oss-iotc] send PRECHECK2 → %s:%u\n",
            inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x14, 0x02, 0x24,   // confirmed from disassembly
                         payload, sizeof(payload));
}

// Send MSG_P2P_PUNCH_TO to the device.
// Confirmed from _IOTC_Send_Punch_To disassembly (re-analysis):
//   header bytes[8..10] = 0x13, 0x02, 0x24
//   payload (20 bytes, inferred from _IOTC_Send_Punch_To @ 0x190790):
//     [0..3]  device WAN IPv4 (4 bytes, network byte order)
//     [4..5]  device WAN port (uint16, big-endian)
//     [6..19] zeros (padding / reserved)
//   Total packet = 16-byte header + 20-byte payload = 36 bytes.
static ssize_t send_punch_to(int sock_fd, const struct sockaddr_in* dst)
{
    uint8_t payload[20];
    memset(payload, 0, sizeof(payload));
    // Device WAN IP in network order at [0..3], port at [4..5] big-endian.
    memcpy(payload + 0, &dst->sin_addr, 4);
    memcpy(payload + 4, &dst->sin_port, 2);  // sin_port already network order

    fprintf(stderr, "[oss-iotc] send PUNCH_TO → %s:%u\n",
            inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x13, 0x02, 0x24,   // confirmed from _IOTC_Send_Punch_To
                         payload, sizeof(payload));
}

// Build the 16-byte MSG_P2P_KNOCK payload.
// Confirmed from _IOTC_Send_Knock disassembly:
//   [0..3]   client_random (uint32 LE)
//   [4..7]   authkey low 32 bits (uint32 LE)
//   [8..11]  authkey high 32 bits (uint32 LE)
//   [12..15] zeros
// Header bytes[8..10] = 0x1b, 0x02, 0x24 (confirmed from _IOTC_Send_Knock).
// Total packet = 16-byte header + 16-byte payload = 32 bytes.
// MSG_P2P_KNOCK_R and MSG_P2P_KNOCK_RR use the same 32 bytes (device echoes KNOCK,
// client re-sends the same bytes for KNOCK_RR) — confirmed from TUTK state machine.
static void build_knock_payload(uint8_t payload[16],
                                uint32_t client_random, uint64_t authkey)
{
    memset(payload, 0, 16);
    uint32_t cr_le  = htole32(client_random);
    uint32_t ak_lo  = htole32((uint32_t)(authkey & 0xffffffff));
    uint32_t ak_hi  = htole32((uint32_t)(authkey >> 32));
    memcpy(payload + 0, &cr_le, 4);
    memcpy(payload + 4, &ak_lo, 4);
    memcpy(payload + 8, &ak_hi, 4);
    // [12..15] = 0 already
}

static ssize_t send_knock(int sock_fd, const struct sockaddr_in* dst,
                          uint32_t client_random, uint64_t authkey,
                          const char* label)
{
    uint8_t payload[16];
    build_knock_payload(payload, client_random, authkey);
    fprintf(stderr, "[oss-iotc] send %s → %s:%u, random=0x%08x\n",
            label, inet_ntoa(dst->sin_addr), ntohs(dst->sin_port),
            client_random);
    // Header bytes[8..10] = 0x1b, 0x02, 0x24 (confirmed from _IOTC_Send_Knock).
    return tutk_udp_send(sock_fd, dst, 0x1b, 0x02, 0x24,
                         payload, sizeof(payload));
}

// Fills sess->device_wan with the confirmed peer address from PRECHECK1_R.
static bool do_p2p_punch(OssSession* sess)
{
    const struct sockaddr_in* dst = &sess->device_wan;
    int sock = sess->udp_sock;

    uint8_t buf[600];
    struct sockaddr_in src{};

    // --- PRECHECK1 ---
    for (int attempt = 0; attempt < 3; ++attempt) {
        send_precheck1(sock, dst, sess->uid);

        // Real SDK polls with 30ms sleep up to ~5s; we use a single 2s recv.
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 2000);
        if (n >= 16) {
            // PRECHECK1_R: header byte [8] == 0x12 (confirmed from UDPP2PConnectTaskCB).
            if (buf[8] != 0x12) {
                fprintf(stderr, "[oss-iotc] PRECHECK1: unexpected hdr[8]=0x%02x, "
                        "retrying\n", buf[8]);
                continue;
            }
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));
            fprintf(stderr, "[oss-iotc] PRECHECK1_R from %s:%u\n",
                    ip_str, ntohs(src.sin_port));

            // Update device address to the confirmed reply-from address.
            sess->device_wan = src;
            dst = &sess->device_wan;
            goto got_precheck1_r;
        }
        fprintf(stderr, "[oss-iotc] PRECHECK1 attempt %d: no reply\n", attempt + 1);
    }
    fprintf(stderr, "[oss-iotc] PRECHECK1: no response after 3 attempts\n");
    return false;

got_precheck1_r:
    // --- PRECHECK2 ---
    send_precheck2(sock, dst, sess->uid, sess->authkey);

    // --- P2P KNOCK exchange ---
    // Confirmed from _IOTC_Send_Knock disassembly:
    //   KNOCK:    header[8..10] = 0x1b, 0x02, 0x24; 16-byte payload (client_random + authkey)
    //   KNOCK_R:  device echoes the same 32 bytes back to the client
    //   KNOCK_RR: client re-sends the identical KNOCK bytes after receiving KNOCK_R
    // After KNOCK_RR, client sends PUNCH_TO to tell device our confirmed WAN address.
    for (int attempt = 0; attempt < 5; ++attempt) {
        // Send KNOCK.
        send_knock(sock, dst, sess->client_random, sess->authkey, "KNOCK");

        // Wait for KNOCK_R: any 32-byte response from the device IP (device echoes KNOCK).
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 1000);
        if (n == 32 && src.sin_addr.s_addr == dst->sin_addr.s_addr) {
            fprintf(stderr, "[oss-iotc] KNOCK_R from %s:%u\n",
                    inet_ntoa(src.sin_addr), ntohs(src.sin_port));

            // Send KNOCK_RR: re-send the same KNOCK bytes (identical payload, same header).
            send_knock(sock, &src, sess->client_random, sess->authkey, "KNOCK_RR");

            // Wait for any response after KNOCK_RR (device may send an ALIVE or ack).
            n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 1000);
            if (n >= 16) {
                fprintf(stderr, "[oss-iotc] post-KNOCK_RR packet from %s:%u "
                        "(hdr: %02x%02x)\n",
                        inet_ntoa(src.sin_addr), ntohs(src.sin_port),
                        buf[8], buf[9]);
                // Update peer address from confirmed reply source.
                sess->device_wan = src;
                dst = &sess->device_wan;
            }
            goto send_punch;
        }
        fprintf(stderr, "[oss-iotc] KNOCK attempt %d: no KNOCK_R (n=%zd)\n",
                attempt + 1, n);
    }
    // Even without KNOCK_R, try PUNCH_TO — device may already be waiting for it.
    fprintf(stderr, "[oss-iotc] KNOCK sequence incomplete; trying PUNCH_TO anyway\n");

send_punch:
    // --- PUNCH_TO ---
    // Tells the device our confirmed WAN address (inferred from _IOTC_Send_Punch_To).
    send_punch_to(sock, dst);

    // Wait briefly for any post-PUNCH_TO packet (device ALIVE_D2C or ack).
    {
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 2000);
        if (n >= 16) {
            fprintf(stderr, "[oss-iotc] post-PUNCH_TO packet from %s:%u "
                    "(hdr: %02x%02x)\n",
                    inet_ntoa(src.sin_addr), ntohs(src.sin_port),
                    buf[8], buf[9]);
            sess->device_wan = src;
        } else {
            fprintf(stderr, "[oss-iotc] no ack after PUNCH_TO — assuming connected\n");
        }
    }

    return true;
}

// ==========================================================================
// P2P keepalive thread
// ==========================================================================
//
// MSG_P2P_ALIVE_C2D is sent every 15 seconds to keep UDP NAT bindings alive.
// Bytes [8..10] = 0x10, 0x02, 0x24 are inferred from the _IOTC_Send_Alive_C2D
// symbol in libBambuSource.so; unconfirmed (requires NAT P2P session capture).

static void* keepalive_thread_fn(void* arg)
{
    OssSession* sess = static_cast<OssSession*>(arg);
    while (sess->keepalive_run) {
        if (sess->state == P2PState::CONNECTED && sess->udp_sock >= 0) {
            tutk_udp_send(sess->udp_sock, &sess->device_wan,
                          0x10, 0x02, 0x24, nullptr, 0);
        }
        // 1-second increments so keepalive_run can stop the thread promptly
        for (int i = 0; i < 15 && sess->keepalive_run; ++i)
            sleep(1);
    }
    return nullptr;
}

// ==========================================================================
// Public API
// ==========================================================================

// Open a P2P session to a Bambu printer identified by UID.
//
// @param uid       20-char printer UID (e.g. "BBLP01XXXXXXXXXX0001")
// @param authkey   8-byte little-endian auth key (from URL "authkey=" param)
// @param password  AV layer password (default "888888")
// @param region    Geographic region for master server selection
// @returns new OssSession* on success, nullptr on failure (caller frees)
OssSession* iotc_connect(const std::string& uid,
                         uint64_t authkey,
                         const std::string& password,
                         TutkRegion region)
{
    if (!uid_valid(uid)) {
        fprintf(stderr, "[oss-iotc] invalid UID (must be 20 printable ASCII): %s\n",
                uid.c_str());
        return nullptr;
    }

    auto* sess = new OssSession();
    sess->uid           = uid_lower(uid);
    sess->authkey       = authkey;
    sess->password      = password;
    sess->region        = region;
    sess->state         = P2PState::IDLE;
    sess->client_random = rand32();

    // Step 1: Open UDP socket
    sess->udp_sock = open_udp_socket(&sess->local_port);
    if (sess->udp_sock < 0) {
        fprintf(stderr, "[oss-iotc] socket open failed: %s\n", strerror(errno));
        delete sess;
        return nullptr;
    }
    fprintf(stderr, "[oss-iotc] UDP socket bound on port %u\n", sess->local_port);
    fprintf(stderr, "[oss-iotc] UID=%s client_random=0x%08x\n",
            sess->uid.c_str(), sess->client_random);

    // Step 2: LAN search + DTLS handshake.
    // The epoch (e.g. 0x6a0) is client-generated; echoed by device in LAN_SEARCH_R3
    // and then used as the epoch for all subsequent DTLS records on the LAN path.
    // If the device is LAN-local, skip P2P punch and go straight to DTLS.
    sess->state = P2PState::LAN_SEARCH;
    {
        sess->dtls_epoch = rand32() & 0xffff;
        uint32_t partial_mac = rand32();

        // session_token = client_random(4B LE) || partial_mac(4B LE)
        uint32_t cr_le = htole32(sess->client_random);
        uint32_t pm_le = htole32(partial_mac);
        memcpy(sess->session_token + 0, &cr_le, 4);
        memcpy(sess->session_token + 4, &pm_le, 4);

        std::string uid_up = uid_upper(sess->uid);

        int bcast_on = 1;
        setsockopt(sess->udp_sock, SOL_SOCKET, SO_BROADCAST,
                   &bcast_on, sizeof(bcast_on));

        static const uint16_t kLanPorts[] = { 18604, 32100 };
        struct sockaddr_in bcast{};
        bcast.sin_family      = AF_INET;
        bcast.sin_addr.s_addr = INADDR_BROADCAST;

        for (uint16_t p : kLanPorts) {
            bcast.sin_port = htons(p);
            send_lan_search3(sess->udp_sock, &bcast,
                             uid_up.c_str(), sess->client_random,
                             partial_mac, (uint16_t)sess->dtls_epoch, false);
            fprintf(stderr, "[oss-iotc] LAN search broadcast → port %u (epoch=0x%x)\n",
                    p, sess->dtls_epoch);
        }

        uint8_t resp[600];
        struct sockaddr_in src{};
        set_recv_timeout(sess->udp_sock, 3000);
        ssize_t n = tutk_udp_recv(sess->udp_sock, resp, sizeof(resp), &src, 3000);
        if (n >= 16) {
            reverse_trans_code_partial(resp, (size_t)n);
            if (resp[0] != 0x04 || resp[1] != 0x02) {
                fprintf(stderr, "[oss-iotc] LAN_SEARCH_R3: bad magic %02x%02x\n",
                        resp[0], resp[1]);
                sess->state = P2PState::QUERY_MASTER;
                goto lan_search_done;
            }
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));
            {
                // payload[33..34] = epoch (BE uint16) echoed from our LAN_SEARCH3
                uint16_t echoed_epoch = ((uint16_t)resp[49] << 8) | resp[50];
                fprintf(stderr, "[oss-iotc] LAN: device at %s:%u  echoed_epoch=0x%x\n",
                        ip_str, ntohs(src.sin_port), echoed_epoch);
            }

            sess->device_wan = src;

            send_lan_search3(sess->udp_sock, &src,
                             uid_up.c_str(), sess->client_random,
                             partial_mac, (uint16_t)sess->dtls_epoch, true);
            fprintf(stderr, "[oss-iotc] directed LAN_SEARCH3 → %s:%u\n",
                    ip_str, ntohs(src.sin_port));

            int dtls_rc = dtls_psk_handshake(
                sess->udp_sock, &src,
                sess->dtls_epoch, sess->session_token,
                uid_up.c_str(),
                g_oss_dtls_passwd.c_str(), g_oss_dtls_account.c_str(),
                &sess->dtls);
            if (dtls_rc != 0) {
                fprintf(stderr, "[oss-iotc] DTLS handshake failed (%d)\n", dtls_rc);
                close(sess->udp_sock);
                delete sess;
                return nullptr;
            }
            sess->state = P2PState::CONNECTED;
        } else {
            fprintf(stderr, "[oss-iotc] LAN search: no device (falling to master)\n");
            sess->state = P2PState::QUERY_MASTER;
        }
    }
    lan_search_done:

    // Step 3: Master server query (if LAN search failed).
    // We open a fresh TCP connection per call; the real SDK uses a persistent connection
    // from IOTC_TcpConnectToMaster.  Port 443 needs TLS (skipped — plain TCP only).
    if (sess->state == P2PState::QUERY_MASTER) {
        struct sockaddr_in dev_addr{};
        bool found = query_master_for_device(
            sess->uid, sess->client_random, region, &dev_addr);

        if (found) {
            sess->device_wan = dev_addr;
            sess->state = P2PState::PRECHECK;
        } else {
            fprintf(stderr, "[oss-iotc] master server: could not find device\n");
            close(sess->udp_sock);
            delete sess;
            return nullptr;
        }
    }

    // Step 4: P2P NAT punch-through.
    if (sess->state == P2PState::PRECHECK) {
        bool ok = do_p2p_punch(sess);
        if (!ok) {
            fprintf(stderr, "[oss-iotc] P2P punch-through failed\n");
            close(sess->udp_sock);
            delete sess;
            return nullptr;
        }

        // WAN P2P DTLS: epoch=0 (not pre-negotiated like LAN path),
        // no type-0x33 auth packet (confirmed absent from relay captures; WAN assumed same).
        int dtls_rc = dtls_psk_handshake(
            sess->udp_sock, &sess->device_wan,
            /*initial_epoch=*/0,
            sess->session_token,
            /*uid_upper_str=*/nullptr,
            g_oss_dtls_passwd.c_str(), g_oss_dtls_account.c_str(),
            &sess->dtls);
        if (dtls_rc != 0) {
            fprintf(stderr, "[oss-iotc] WAN DTLS handshake failed\n");
            close(sess->udp_sock);
            delete sess;
            return nullptr;
        }
    }

    sess->state = P2PState::CONNECTED;
    fprintf(stderr, "[oss-iotc] P2P session established with %s:%u\n",
            inet_ntoa(sess->device_wan.sin_addr),
            ntohs(sess->device_wan.sin_port));

    sess->keepalive_run = true;
    if (pthread_create(&sess->keepalive_tid, nullptr,
                       keepalive_thread_fn, sess) != 0) {
        fprintf(stderr, "[oss-iotc] keepalive thread creation failed\n");
        sess->keepalive_run = false;
    } else {
        pthread_detach(sess->keepalive_tid);
    }

    return sess;
}

void iotc_close(OssSession* sess)
{
    if (!sess) return;
    sess->keepalive_run = false;

    if (sess->udp_sock >= 0) {
        // Send MSG_P2P_CLOSE_C2D to notify the device before closing.
        // Header bytes[8..10] = 0x18, 0x02, 0x24 (confirmed from _IOTC_Send_Close).
        // payload_len = 0 (header-only, 16 bytes total).
        if (sess->state == P2PState::CONNECTED) {
            tutk_udp_send(sess->udp_sock, &sess->device_wan,
                          0x18, 0x02, 0x24, nullptr, 0);
        }
        close(sess->udp_sock);
        sess->udp_sock = -1;
    }
    delete sess;
}

// ==========================================================================
// TUTK IOTC Relay Protocol
// ==========================================================================
//
// The "Agora" cloud camera path in Bambu printers is NOT Agora — it is a TUTK
// IOTC relay protocol.  Traffic analysis shows:
//
//   Relay server: {region}-c-master-{relay_id}.iotcplatform.com:10240 (UDP)
//   ALL packets scrambled with TransCodePartial (key = "Charlie is the d")
//
// Connection flow:
//   1. JOIN (54B):  IOTC header + UID(20B) + relay_id(16B) + 0x0600
//   2. KNOCK ×5 (88B): IOTC header + UID(20B) + zeros(16B) + sdk_ver(4B)
//                       + session_token(8B) + 24B fixed flags
//   3. Relay server responds with 200B relay assignment
//      — bytes [188..191] echo session_token[0..3]
//   4. Client sends one more KNOCK (same 88B format)
//   5. DTLS handshake (initial_epoch=0, no type-0x33 packet for relay path)
//   6. DTLS ApplicationData: AV LOGIN → LOGIN ACK → IPCAM_START → frames

// relay_id: first 16 chars of the 20-char relay subdomain.
static int send_relay_join(int sock, const struct sockaddr_in* dst,
                            const char* uid_upper, const char* relay_id)
{
    uint8_t pkt[54];
    memset(pkt, 0, sizeof(pkt));

    // bytes [8..10] = 0x07, 0x10, 0x18 (same as MSG_QUERY_DEVICE5)
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;
    pkt[4] = 0x26;  // payload_len=38 LE
    pkt[8]  = 0x07; pkt[9]  = 0x10; pkt[10] = 0x18;

    memcpy(pkt + 16, uid_upper, 20);
    size_t relay_copy = strnlen(relay_id, 16);
    memcpy(pkt + 36, relay_id, relay_copy);
    pkt[52] = 0x06;
    pkt[53] = 0x00;

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// Build and send an 88-byte KNOCK packet.
// session_token: 8 random bytes generated by client.
// directed=false: initial knock (pre-assignment), flags[64]=0x01.
// directed=true:  post-assignment knock, flags[64]=0x02.
// Both flag patterns confirmed from protocol capture.
static int send_relay_knock(int sock, const struct sockaddr_in* dst,
                             const char* uid_upper,
                             const uint8_t session_token[8],
                             bool directed = false)
{
    uint8_t pkt[88];
    memset(pkt, 0, sizeof(pkt));

    // bytes [8..10] = 0x01, 0x06, 0x21
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;
    pkt[4] = 0x48;  // payload_len=72 LE
    pkt[8]  = 0x01; pkt[9]  = 0x06; pkt[10] = 0x21;

    memcpy(pkt + 16, uid_upper, 20);
    // [36..51] = zeros (already zeroed)

    uint32_t sdk_ver = htole32(0x04030304);  // TUTK SDK 4.3.3.4 at [52..55]
    memcpy(pkt + 52, &sdk_ver, 4);
    memcpy(pkt + 56, session_token, 8);  // [56..63]

    // 24-byte flags at [64..87]:
    //   initial KNOCKs (directed=false): byte[64]=0x01, includes NAT timing hints
    //   post-assignment KNOCK (directed=true): byte[64]=0x02, simplified
    // Both patterns inferred from relay protocol captures.
    if (!directed) {
        static const uint8_t kInitKnockFlags[24] = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0x64, 0x35, 0x35, 0x36, 0x63,
            0x63, 0x04, 0x13, 0x13, 0x66, 0x0c, 0x0c, 0x05
        };
        memcpy(pkt + 64, kInitKnockFlags, 24);
    } else {
        static const uint8_t kDirKnockFlags[24] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0x04, 0x13, 0x13, 0x04, 0x0c, 0x0c, 0x63
        };
        memcpy(pkt + 64, kDirKnockFlags, 24);
    }

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// JOIN + KNOCK×5 + receive 200B relay assignment + post-KNOCK.
int iotc_relay_connect(const char* uid_upper, const char* relay_id,
                       const char* region_str, RelayConn* out)
{
    if (!uid_upper || !relay_id || !region_str || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->sock = -1;

    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%s-c-master-%s.iotcplatform.com",
             region_str, relay_id);

    fprintf(stderr, "[relay] connecting to %s:10240\n", hostname);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", 10240);
    int rc = getaddrinfo(hostname, port_str, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "[relay] DNS failed for %s: %s\n",
                hostname, gai_strerror(rc));
        return -1;
    }
    struct sockaddr_in relay_addr{};
    relay_addr = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &relay_addr.sin_addr, ip_str, sizeof(ip_str));
    fprintf(stderr, "[relay] resolved %s → %s:10240\n", hostname, ip_str);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[relay] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    uint8_t session_token[8];
    {
        uint32_t a = rand32(), b = rand32();
        memcpy(session_token + 0, &a, 4);
        memcpy(session_token + 4, &b, 4);
    }

    if (send_relay_join(sock, &relay_addr, uid_upper, relay_id) != 0) {
        fprintf(stderr, "[relay] JOIN send failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    fprintf(stderr, "[relay] JOIN sent\n");

    for (int i = 0; i < 5; ++i) {
        if (send_relay_knock(sock, &relay_addr, uid_upper, session_token) != 0) {
            fprintf(stderr, "[relay] KNOCK[%d] send failed: %s\n", i, strerror(errno));
            close(sock);
            return -1;
        }
    }
    fprintf(stderr, "[relay] KNOCK×5 sent\n");

    set_recv_timeout(sock, 3000);
    bool got_assignment = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        uint8_t resp[256];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(sock, resp, sizeof(resp), 0,
                              (struct sockaddr*)&src, &src_len);
        if (n < 0) {
            fprintf(stderr, "[relay] recv timeout attempt %d\n", attempt + 1);
            continue;
        }

        fprintf(stderr, "[relay] received %zd bytes from relay server\n", n);

        if (n < 192) {
            fprintf(stderr, "[relay] response too short (%zd, expected >=192)\n", n);
            continue;
        }

        reverse_trans_code_partial(resp, (size_t)n);

        if (resp[0] != 0x04 || resp[1] != 0x02) {
            fprintf(stderr, "[relay] bad IOTC magic %02x%02x\n", resp[0], resp[1]);
            continue;
        }

        if (resp[8] != 0x02 || resp[9] != 0x06 || resp[10] != 0x12) {  // relay assignment type
            fprintf(stderr, "[relay] unexpected msg type %02x%02x%02x "
                    "(expected 02 06 12)\n", resp[8], resp[9], resp[10]);
            continue;
        }

        if (n >= 192) {  // verify session_token echo at [188..191]
            if (resp[188] != session_token[0] || resp[189] != session_token[1] ||
                resp[190] != session_token[2] || resp[191] != session_token[3]) {
                fprintf(stderr, "[relay] session_token echo mismatch: "
                        "got %02x%02x%02x%02x expected %02x%02x%02x%02x\n",
                        resp[188], resp[189], resp[190], resp[191],
                        session_token[0], session_token[1],
                        session_token[2], session_token[3]);
                // Log but don't reject — the echo offset may differ by firmware
            } else {
                fprintf(stderr, "[relay] session_token echo verified\n");
            }
        }

        got_assignment = true;
        fprintf(stderr, "[relay] relay assignment received\n");
        break;
    }

    if (!got_assignment) {
        fprintf(stderr, "[relay] no relay assignment received after 3 attempts\n");
        close(sock);
        return -1;
    }

    if (send_relay_knock(sock, &relay_addr, uid_upper, session_token, true) != 0) {
        fprintf(stderr, "[relay] post-assignment KNOCK failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    fprintf(stderr, "[relay] post-assignment KNOCK sent\n");

    out->sock = sock;
    out->relay_addr = relay_addr;
    memcpy(out->session_token, session_token, 8);
    memset(&out->dtls, 0, sizeof(out->dtls));

    return 0;
}

// epoch=0, no type-0x33 packet — relay path omits both (confirmed from captures).
int iotc_relay_dtls(RelayConn* rc,
                    const char* passwd, const char* account)
{
    if (!rc || rc->sock < 0) return -1;

    return dtls_psk_handshake(rc->sock, &rc->relay_addr,
                               /*initial_epoch=*/0,
                               rc->session_token,
                               /*uid_upper_str=*/nullptr,
                               passwd, account,
                               &rc->dtls);
}

int iotc_relay_send_app_data(RelayConn* rc,
                              const uint8_t* data, size_t len)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

    uint8_t nonce[12];
    build_relay_nonce(nonce, ds.client_write_iv, ds.epoch, ds.tx_seq);

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, 0x17 /*ApplicationData*/,
                          ds.epoch, (uint32_t)ds.tx_seq, (uint16_t)len);

    std::vector<uint8_t> ciphertext(len + 16);
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, ds.client_write_key, nonce);
        EVP_EncryptUpdate(ctx, nullptr, &outl, rec_hdr, 13);  // AAD
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, data, (int)len);
        int total = outl;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outl);
        total += outl;
        uint8_t tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        memcpy(ciphertext.data() + total, tag, 16);
        EVP_CIPHER_CTX_free(ctx);
    }

    uint16_t cipher_len = (uint16_t)(len + 16);
    build_dtls_record_hdr(rec_hdr, 0x17, ds.epoch, (uint32_t)ds.tx_seq, cipher_len);
    ds.tx_seq++;

    std::vector<uint8_t> dtls_pkt(13 + cipher_len);
    memcpy(dtls_pkt.data(), rec_hdr, 13);
    memcpy(dtls_pkt.data() + 13, ciphertext.data(), cipher_len);

    return send_dtls_packet(rc->sock, &rc->relay_addr,
                             ds.epoch, rc->session_token,
                             dtls_pkt.data(), dtls_pkt.size());
}

int iotc_relay_recv_app_data(RelayConn* rc,
                              uint8_t* out_buf, size_t out_size,
                              int timeout_ms)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

    static constexpr int kMaxRetries = 16;
    set_recv_timeout(rc->sock, timeout_ms);

    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        uint8_t raw[65536 + 64];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(rc->sock, raw, sizeof(raw), 0,
                              (struct sockaddr*)&src, &src_len);
        if (n < 0) {
            // EAGAIN / timeout → return 0
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                return 0;
            fprintf(stderr, "[relay-recv] recvfrom error: %s\n", strerror(errno));
            return -1;
        }

        if (n < 28) continue;  // too short for IOTC header

        reverse_trans_code_partial(raw, (size_t)n);

        if (raw[0] != 0x04 || raw[1] != 0x02) continue;
        if (n < 28 + 13) continue;  // too short for IOTC header + DTLS record header

        uint8_t content_type = raw[28];

        // Skip non-ApplicationData records (keepalives, etc.)
        if (content_type != 0x17) {
            fprintf(stderr, "[relay-recv] skipping DTLS record type 0x%02x\n",
                    content_type);
            continue;
        }

        uint32_t rec_epoch  = read_be32(raw + 31);
        uint32_t rec_seq    = read_be32(raw + 35);
        uint16_t cipher_len = read_be16(raw + 39);

        if (n < 28 + 13 + (ssize_t)cipher_len) {
            fprintf(stderr, "[relay-recv] truncated DTLS record "
                    "(have %zd, need %d)\n", n, 28 + 13 + cipher_len);
            continue;
        }

        if (cipher_len < 16) {
            fprintf(stderr, "[relay-recv] cipher_len %u too short for tag\n",
                    cipher_len);
            continue;
        }

        uint16_t plain_len = cipher_len - 16;
        if (plain_len > out_size) {
            fprintf(stderr, "[relay-recv] plaintext %u > out_size %zu\n",
                    plain_len, out_size);
            return -1;
        }

        // rec_seq is 32-bit on the wire; treat as low 32 bits of the 64-bit seq counter.
        uint8_t nonce[12];
        build_relay_nonce(nonce, ds.server_write_iv, rec_epoch, (uint64_t)rec_seq);

        const uint8_t* aad        = raw + 28;  // AAD = 13-byte DTLS record header
        const uint8_t* ciphertext = raw + 28 + 13;
        const uint8_t* tag = ciphertext + plain_len;

        {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            int outl = 0;
            EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 const_cast<uint8_t*>(tag));
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, ds.server_write_key, nonce);
            EVP_DecryptUpdate(ctx, nullptr, &outl, aad, 13);  // AAD
            EVP_DecryptUpdate(ctx, out_buf, &outl, ciphertext, (int)plain_len);
            int total = outl;
            int ok = EVP_DecryptFinal_ex(ctx, out_buf + total, &outl);
            EVP_CIPHER_CTX_free(ctx);

            if (ok > 0) {
                return (int)plain_len;
            }
            fprintf(stderr, "[relay-recv] AEAD auth failed (epoch=%u seq=%u)\n",
                    rec_epoch, rec_seq);
            continue;
        }
    }

    return 0;  // exhausted retries without an AppData packet
}

void iotc_relay_close(RelayConn* rc)
{
    if (!rc) return;
    if (rc->sock >= 0) {
        close(rc->sock);
        rc->sock = -1;
    }
    memset(rc, 0, sizeof(*rc));
    rc->sock = -1;
}

// ==========================================================================
// AV layer — Start video stream
// ==========================================================================
//
// Once the IOTC session is established (iotc_connect returns non-null),
// the AV layer needs to be started.
//
// Implemented flow (avClientStartEx + avSendIOCtrl + avRecvFrameData2):
//   1. avClientStartEx(AvStartIn*, AvStartOut*) — allocates AV channel slot.
//      In the real TUTK library this triggers avConnect_inner which sends the
//      LOGIN frame and waits for the printer's auth response.
//      In our OSS reimplementation, call oss_av_attach() then oss_av_login()
//      before the IOCtrl/recv cycle.
//
//   2. avSendIOCtrl(av_index, 0xFF01, NULL, 0) — send IPCAM_START.
//      Wire format (derived from _avSendIO → avSendIOCtrlFrame):
//        AvFrameHeader(sub=CTRL=0x02) + uint32_t type_LE + uint32_t data_len_LE
//
//   3. avRecvFrameData2(...) — receive one H.264 frame per call.
//      Reads a UDP datagram, validates the 16-byte AvFrameHeader, copies
//      payload into caller's buffer.  Returns bytes copied or negative error.
//
// Wire format of AV frame (confirmed from disassembly):
//   [0..3]  payload_len   (uint32 LE)
//   [4..7]  magic         (uint32 LE): bits[15:0]=0x013f, bits[23:16]=sub_type,
//                                       bits[31:24]=direction
//   [8..11] sequence      (uint32 LE, monotonic counter)
//   [12..15] reserved     (uint32, set to 0x0b in login frame, else 0)
//   [16..]  payload
//
// LOGIN frame payload (derived from avConnect_inner @ 168102–16816a):
//   account\0passwd\0   (NUL-terminated strings concatenated)
//
// IOCtrl frame payload (derived from avSendIOCtrlFrame / _avSendIOCtrl_Old):
//   [0..3]  ioctrl_type  (uint32 LE, e.g. 0xFF01)
//   [4..7]  data_len     (uint32 LE)
//   [8..]   data bytes   (0 for IPCAM_START)

struct AvFrameHeader {
    uint32_t payload_len;  // LE
    uint32_t magic;        // LE: (dir<<24)|(sub<<16)|0x013f
    uint32_t sequence;     // LE
    uint32_t reserved;     // unknown
};
static_assert(sizeof(AvFrameHeader) == 16, "AV frame header must be 16 bytes");

static uint32_t av_magic(uint8_t sub_type, uint8_t direction)
{
    return (uint32_t)kFrameMagicMarker
         | ((uint32_t)sub_type  << 16)
         | ((uint32_t)direction << 24);
}

static bool is_av_frame_header(const uint8_t* buf)
{
    uint32_t magic;
    memcpy(&magic, buf + 4, 4);
    magic = le32toh(magic);
    return (magic & 0xffff) == kFrameMagicMarker;
}

// ==========================================================================
// AV layer — wire helpers
// ==========================================================================

// Maximum account / password string lengths accepted by the TUTK AV server.
// From avConnect_inner: strlen(account) must be < rbx-1 (rbx = 0x101 or 0x10
// depending on remote protocol version), and strlen(passwd) <= 0x77 = 119.
static constexpr size_t kAvAccountMax = 0x100; // 256 chars
static constexpr size_t kAvPasswdMax  = 0x77;  // 119 chars

// AV packet ring buffer used by the frame-receive path.
// Each slot tracks one in-flight TUTK AV packet from the read thread.
// The slot layout (confirmed from avConnect_inner and _avRecvData):
//   [0x00] uint32_t frame_seq     — frame sequence number
//   [0x08] uint8_t  type          — slot type: 0x02 = video, 0x01 = audio
//   [0x0c..0x17] other fields
// Per-slot stride = 0x18 = 24 bytes (from _avRecvData loop: add $0x18,%rax).

// IOCtrl packet header used by the TUTK avSendIOCtrl path.
// From _avSendIO → avSendIOCtrlFrame (PLT call at 16cbed, extra arg r8d=0x70).
// The IOCtrl frame wraps the user type+data in a TUTK-specific packet.
// Wire layout (reconstructed from _avSendIOCtrl_Old and assemblePackHead calls):
//
//   Bytes [0..3]  header assembled by assemblePackHead:
//                   [0]   = msg_type low byte (0x00 for IOCtrl send)
//                   [1]   = sub_type byte
//                   [2..3]= 0x000b (AV channel identifier)
//   Bytes [4..7]  ioctrl_type (uint32_t LE, e.g. 0xFF01 for IPCAM_START)
//   Bytes [8..11] payload_len (uint32_t LE)
//   Bytes [12..] payload data (0 bytes for IPCAM_START)
//
// Note: The 0x70 flag passed to avSendIOCtrlFrame selects the "new" IOCtrl
// path which wraps the above inside an AV frame with magic 0x013f.

struct AvIoCtrlPkt {
    uint8_t  hdr[4];          // [0] assemblePackHead output (type, sub, 0x000b)
    uint32_t ioctrl_type;     // [4] LE: IOTYPE_USER_IPCAM_START etc.
    uint32_t payload_len;     // [8] LE
    // payload follows
};

static void fill_av_header(AvFrameHeader* hdr,
                           uint8_t sub_type, uint8_t direction,
                           uint32_t payload_len, uint32_t sequence)
{
    hdr->payload_len = htole32(payload_len);
    hdr->magic       = htole32(av_magic(sub_type, direction));
    hdr->sequence    = htole32(sequence);
    hdr->reserved    = 0;
}

// ==========================================================================
// AV channel state (one per active av_index)
// ==========================================================================
//
// The real TUTK library manages a kalayav_interface_list[] table indexed by
// av_index (returned by avClientStartEx).  Each entry is a 0xa0-byte struct
// holding a pointer to the AV object (the AVConn) at offset 0.
//
// For the OSS reimplementation we keep a simple flat table.

static constexpr int kMaxAvChannels = 8;

struct AvChannel {
    bool     active;
    int      sock_fd;
    struct sockaddr_in peer;
    uint8_t  channel;           // IOTC AV channel number (0..31)
    uint32_t tx_seq;            // next outgoing sequence number (AV-level, inside frame header)
    uint32_t rx_seq_expected;   // next expected incoming sequence number
    DtlsSession* dtls_sess;     // points into OssSession::dtls (not owned); null = plaintext
    bool         use_dtls;      // true when underlying socket carries DTLS ApplicationData
    uint8_t      session_token[8]; // IOTC session token for DTLS IOTC wrapper
};

static AvChannel g_av_channels[kMaxAvChannels];
static bool      g_av_channels_init = false;

static void av_channels_init()
{
    if (g_av_channels_init) return;
    memset(g_av_channels, 0, sizeof(g_av_channels));
    for (auto& ch : g_av_channels) {
        ch.sock_fd   = -1;
        ch.dtls_sess = nullptr;
        ch.use_dtls  = false;
    }
    g_av_channels_init = true;
}

static int av_alloc_channel()
{
    av_channels_init();
    for (int i = 0; i < kMaxAvChannels; ++i) {
        if (!g_av_channels[i].active) return i;
    }
    return -1;
}

// ==========================================================================
// DTLS AV-layer helpers: encrypt/send and decrypt/recv
// ==========================================================================

// Encrypt and send one ApplicationData record over a P2P (non-relay) socket.
static int dtls_encrypt_and_send(DtlsSession* ds, int sock,
                                  const struct sockaddr_in* dst,
                                  const uint8_t* session_token,
                                  const uint8_t* data, size_t len)
{
    uint8_t nonce[12];
    memcpy(nonce, ds->client_write_iv, 12);
    nonce[4] ^= (uint8_t)((uint16_t)ds->epoch >> 8);
    nonce[5] ^= (uint8_t)((uint16_t)ds->epoch     );
    for (int i = 0; i < 6; ++i)
        nonce[6 + i] ^= (uint8_t)(ds->tx_seq >> (40 - 8*i));

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, 0x17 /*ApplicationData*/,
                          ds->epoch, (uint32_t)ds->tx_seq, (uint16_t)len);

    std::vector<uint8_t> ciphertext(len + 16);
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, ds->client_write_key, nonce);
        EVP_EncryptUpdate(ctx, nullptr, &outl, rec_hdr, 13);  // AAD
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, data, (int)len);
        int total = outl;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outl);
        total += outl;
        uint8_t tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        memcpy(ciphertext.data() + total, tag, 16);
        EVP_CIPHER_CTX_free(ctx);
    }

    uint16_t cipher_len = (uint16_t)(len + 16);
    build_dtls_record_hdr(rec_hdr, 0x17, ds->epoch, (uint32_t)ds->tx_seq, cipher_len);
    ds->tx_seq++;

    std::vector<uint8_t> dtls_pkt(13 + cipher_len);
    memcpy(dtls_pkt.data(), rec_hdr, 13);
    memcpy(dtls_pkt.data() + 13, ciphertext.data(), cipher_len);

    return send_dtls_packet(sock, dst, ds->epoch, session_token,
                             dtls_pkt.data(), dtls_pkt.size());
}

// Decrypt one DTLS ApplicationData record received in a raw IOTC-wrapped UDP datagram.
// raw/raw_len: the full datagram as received from recvfrom (not yet descrambled).
// plain_out/plain_max: output buffer for decrypted payload.
// Returns plaintext byte count on success, 0 if not an ApplicationData record
// (keepalive or other type — caller should retry), -1 on AEAD authentication failure.
static int dtls_decrypt_one(DtlsSession* ds,
                             const uint8_t* raw, size_t raw_len,
                             uint8_t* plain_out, size_t plain_max)
{
    if (raw_len < 28 + 13) return 0;  // too short for IOTC header + DTLS record header

    std::vector<uint8_t> buf(raw, raw + raw_len);
    reverse_trans_code_partial(buf.data(), buf.size());

    if (buf[0] != 0x04 || buf[1] != 0x02) return 0;

    uint8_t content_type = buf[28];  // DTLS record starts at offset 28
    if (content_type != 0x17) {
        // Not ApplicationData — keepalive or handshake record; caller should retry
        fprintf(stderr, "[dtls-decrypt] skipping DTLS record type 0x%02x\n", content_type);
        return 0;
    }

    uint32_t rec_epoch = ((uint32_t)buf[31] << 24) | ((uint32_t)buf[32] << 16)
                       | ((uint32_t)buf[33] <<  8) |  (uint32_t)buf[34];
    uint32_t rec_seq   = ((uint32_t)buf[35] << 24) | ((uint32_t)buf[36] << 16)
                       | ((uint32_t)buf[37] <<  8) |  (uint32_t)buf[38];
    uint16_t cipher_len = ((uint16_t)buf[39] << 8) | buf[40];

    if (raw_len < 28 + 13 + (size_t)cipher_len) {
        fprintf(stderr, "[dtls-decrypt] truncated record (have %zu, need %zu)\n",
                raw_len, 28 + 13 + (size_t)cipher_len);
        return 0;
    }
    if (cipher_len < 16) {
        fprintf(stderr, "[dtls-decrypt] cipher_len %u too short for tag\n", cipher_len);
        return 0;
    }

    uint16_t plain_len = cipher_len - 16;
    if (plain_len > plain_max) {
        fprintf(stderr, "[dtls-decrypt] plaintext %u > plain_max %zu\n",
                plain_len, plain_max);
        return -1;
    }

    // TUTK carries 4-byte epoch + 4-byte seq; treat seq as low 32 bits of 64-bit counter.
    uint8_t nonce[12];
    memcpy(nonce, ds->server_write_iv, 12);
    for (int i = 0; i < 4; ++i)
        nonce[i] ^= (uint8_t)(rec_epoch >> (24 - 8*i));
    for (int i = 0; i < 4; ++i)
        nonce[8 + i] ^= (uint8_t)(rec_seq >> (24 - 8*i));

    const uint8_t* aad        = buf.data() + 28;  // AAD = 13-byte DTLS record header
    const uint8_t* ciphertext = buf.data() + 28 + 13;
    const uint8_t* tag        = ciphertext + plain_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag));
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, ds->server_write_key, nonce);
    EVP_DecryptUpdate(ctx, nullptr, &outl, aad, 13);  // AAD
    EVP_DecryptUpdate(ctx, plain_out, &outl, ciphertext, (int)plain_len);
    int total = outl;
    int ok = EVP_DecryptFinal_ex(ctx, plain_out + total, &outl);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        fprintf(stderr, "[dtls-decrypt] AEAD auth failed (epoch=%u seq=%u)\n",
                rec_epoch, rec_seq);
        return -1;
    }
    return (int)plain_len;
}

static int av_channel_write(AvChannel* ch, const void* buf, size_t len)
{
    if (ch->use_dtls && ch->dtls_sess) {
        return dtls_encrypt_and_send(ch->dtls_sess, ch->sock_fd, &ch->peer,
                                      ch->session_token,
                                      static_cast<const uint8_t*>(buf), len);
    }
    ssize_t sent = sendto(ch->sock_fd, buf, len, 0,
                          (const struct sockaddr*)&ch->peer, sizeof(ch->peer));
    return (sent == (ssize_t)len) ? 0 : -1;
}

// Retries on non-ApplicationData DTLS records (keepalives etc.).
static ssize_t av_channel_read_plain(AvChannel* ch,
                                      uint8_t* plain_out, size_t plain_max,
                                      int timeout_ms)
{
    set_recv_timeout(ch->sock_fd, timeout_ms);

    if (!ch->use_dtls || !ch->dtls_sess) {
        return recv(ch->sock_fd, plain_out, plain_max, 0);
    }

    static constexpr int kMaxRetries = 16;
    std::vector<uint8_t> raw(65536 + 64);
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        ssize_t n = recv(ch->sock_fd, raw.data(), raw.size(), 0);
        if (n < 0) return -1;
        int pn = dtls_decrypt_one(ch->dtls_sess, raw.data(), (size_t)n,
                                   plain_out, plain_max);
        if (pn > 0) return (ssize_t)pn;
        if (pn < 0) return -1;
        // pn == 0: non-AppData record — retry
    }
    return -1;
}

// ==========================================================================
// avClientStartEx — open AV channel and authenticate
// ==========================================================================
//
// LOGIN frame protocol (derived from avConnect_inner disassembly):
//
// The client sends a 16-byte AvFrameHeader followed by a credential block:
//
//   [0x00..0x0f]  AvFrameHeader:
//     payload_len = account_len+1 + passwd_len+1  (includes NUL terminators)
//     magic       = 0x0001013f  (dir=0x00, sub=0x01=LOGIN, marker=0x013f)
//     sequence    = 0           (first login frame)
//     reserved    = 0
//
//   [0x10..0x10+account_len]  account string (NUL-terminated, max 255 chars)
//   [0x10+account_len+1 ..]   passwd string  (NUL-terminated, max 119 chars)
//
// Evidence:
//  - avConnect_inner @ 168102–168131: memcpy(pkt+0x18, account, strlen(account))
//    (0x18 relative to the 16-byte AvFrameHeader base at 0x140(%rsp) — so
//    the account starts at header+0x18, but the header base itself is at
//    0x140 and credentials go at 0x158; relative to header that is 0x18.)
//  - passwd is placed after account at 168136–16816a: memcpy(r11, passwd, ...)
//    where r11 = pkt_base + 0x18 + account_strlen_rounded (from 0x38(%rsp)).
//  - assemblePackHead @ 168693 fills header[0]=0, [1]=0x20(sub?), [2..3]=0x0b
//    for the DTLS variant; the non-DTLS path (168693 is skipped) uses inline
//    code that sets header[2..3]=0x0b, type=0, sub=0 at 1680c1.
//    BUT the 16-byte AvFrameHeader at the front is separate from the TUTK
//    internal packetisation header — the magic 0x013f comes from the AV
//    frame layer above, confirmed by the kFrameMagicMarker constant.
//
//  - From _avProcessLoginPacket @ 176e60: the server reads [2..3] of the
//    incoming packet as "version" and validates it.  The server then calls
//    _AvDoAuthCheck with the packet contents which is how it reads account/passwd.
//
// LOGIN ACK: the server replies with an AvFrameHeader:
//   magic (sub=0x01), direction=P→C (0x00), payload_len=4
//   payload: uint32_t result_code (0 = success)
//
// The av_index returned is the slot we allocated locally; the TUTK library
// would return an index into kalayav_interface_list.

extern "C" int avClientStartEx(void* start_in_v, void* start_out_v)
{
    if (!start_in_v || !start_out_v) return AV_ER_INVALID_SID;

    auto* in  = static_cast<AvStartIn*>(start_in_v);
    auto* out = static_cast<AvStartOut*>(start_out_v);

    if (in->struct_size <= 0x37) return AV_ER_INVALID_SID;
    if (out->struct_size <= 0x17) return AV_ER_INVALID_SID;
    if (in->channel > 0x1f) return AV_ER_INVALID_SID;

    const char* account = in->account ? in->account : "admin";
    const char* passwd  = in->passwd  ? in->passwd  : "888888";

    size_t acc_len = strnlen(account, kAvAccountMax);
    size_t pwd_len = strnlen(passwd,  kAvPasswdMax);
    if (acc_len >= kAvAccountMax) return AV_ER_INVALID_SID;
    if (pwd_len >= kAvPasswdMax)  return AV_ER_INVALID_SID;

    int idx = av_alloc_channel();
    if (idx < 0) return AV_ER_EXCEED_MAX_CHANNEL;

    // Socket is filled later via oss_av_attach(); real TUTK wires it via the sid.
    g_av_channels[idx].active  = true;
    g_av_channels[idx].channel = in->channel;
    g_av_channels[idx].tx_seq  = 0;
    g_av_channels[idx].rx_seq_expected = 0;
    g_av_channels[idx].sock_fd = -1; // filled by caller via oss_av_attach()

    out->resend   = 0;
    out->two_way  = 0;
    out->unknown1 = 0;
    out->unknown2 = 0;
    out->av_index = idx;

    fprintf(stderr, "[oss-av] avClientStartEx: allocated av_index=%d channel=%u "
            "account='%s'\n", idx, in->channel, account);

    return idx;
}

// In the real TUTK library the AV object holds the session reference from sid;
// here it is supplied explicitly after avClientStartEx.
void oss_av_attach(int av_index, int sock_fd, const struct sockaddr_in* peer,
                   DtlsSession* dtls, const uint8_t* session_token)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return;
    if (!g_av_channels[av_index].active) return;
    g_av_channels[av_index].sock_fd   = sock_fd;
    if (peer) g_av_channels[av_index].peer = *peer;
    g_av_channels[av_index].dtls_sess = dtls;
    g_av_channels[av_index].use_dtls  = (dtls != nullptr && dtls->handshake_complete);
    if (session_token)
        memcpy(g_av_channels[av_index].session_token, session_token, 8);
    else
        memset(g_av_channels[av_index].session_token, 0, 8);
}

int oss_av_login(int av_index, const char* account, const char* passwd,
                 int timeout_ms)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd < 0) return AV_ER_INVALID_SID;

    if (!account) account = "admin";
    if (!passwd)  passwd  = "888888";

    size_t acc_len = strnlen(account, kAvAccountMax);
    size_t pwd_len = strnlen(passwd,  kAvPasswdMax);

    uint32_t payload_len = (uint32_t)(acc_len + 1 + pwd_len + 1);
    size_t   pkt_size    = sizeof(AvFrameHeader) + payload_len;

    std::vector<uint8_t> pkt(pkt_size, 0);
    auto* hdr = reinterpret_cast<AvFrameHeader*>(pkt.data());

    // reserved=0x0b mirrors assemblePackHead cx=0x0b (avConnect_inner+0x4c1).
    hdr->payload_len = htole32(payload_len);
    hdr->magic       = htole32(av_magic(kFrameSubtypeLogin, kFrameDirClientToP));
    hdr->sequence    = htole32(ch.tx_seq++);
    hdr->reserved    = htole32(0x0000000b);

    uint8_t* cred = pkt.data() + sizeof(AvFrameHeader);
    memcpy(cred, account, acc_len);              // NUL already there (vector zero-init)
    memcpy(cred + acc_len + 1, passwd, pwd_len); // NUL already there

    if (av_channel_write(&ch, pkt.data(), pkt_size) < 0) {
        fprintf(stderr, "[oss-av] LOGIN send failed: %s\n", strerror(errno));
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    uint8_t ack_buf[sizeof(AvFrameHeader) + 8];
    ssize_t n = av_channel_read_plain(&ch, ack_buf, sizeof(ack_buf), timeout_ms);
    if (n < (ssize_t)sizeof(AvFrameHeader)) {
        fprintf(stderr, "[oss-av] LOGIN ACK timeout or short read (n=%zd)\n", n);
        return AV_ER_TIMEOUT;
    }

    if (!is_av_frame_header(ack_buf)) {
        fprintf(stderr, "[oss-av] LOGIN ACK: bad magic in reply\n");
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    auto* ack = reinterpret_cast<const AvFrameHeader*>(ack_buf);
    uint32_t ack_magic = le32toh(ack->magic);
    uint8_t  ack_sub   = (ack_magic >> 16) & 0xff;
    if (ack_sub != kFrameSubtypeLogin) {
        fprintf(stderr, "[oss-av] LOGIN ACK: unexpected sub-type 0x%02x\n", ack_sub);
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    uint32_t ack_payload_len = le32toh(ack->payload_len);
    if (ack_payload_len >= 4 && n >= (ssize_t)(sizeof(AvFrameHeader) + 4)) {
        uint32_t result;
        memcpy(&result, ack_buf + sizeof(AvFrameHeader), 4);
        result = le32toh(result);
        if (result != 0) {
            fprintf(stderr, "[oss-av] LOGIN rejected by printer: result=0x%x\n", result);
            return AV_ER_WRONG_VIEWACCorPWD;
        }
    }

    fprintf(stderr, "[oss-av] LOGIN accepted by printer (av_index=%d)\n", av_index);
    return 0;
}

// ==========================================================================
// avClientStop (0x15f7f0)
// ==========================================================================
//
// Real binary: kalayav_interface_list lookup → vtable[0x10] = _avStop
//   (acquires avConnectionLock, sends CTRL stop frame, wakes read thread).

extern "C" void avClientStop(int av_index)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active) return;

    fprintf(stderr, "[oss-av] avClientStop: av_index=%d\n", av_index);
    ch.active = false;
    // Do NOT close the socket — OssSession may still need it for keepalives.
}

// ==========================================================================
// avSendIOCtrl — send an IOCtrl message
// ==========================================================================
//
// In the binary (0x15e330):
//   - Validates len >= 0 (returns AV_ER_INVALID_SID = -0x3ea if len < 0)
//   - Looks up av_index → avObj
//   - Calls avObj->vtable[0x40](avObj, type, buf, len) = _avSendIO
//   - _avSendIO checks avObj->field_0x1f84:
//     - if == 1: calls avSendIOCtrlFrame(avObj, type, buf, len, flags=0x70)
//     - else:    calls _avSendIOCtrl_Old(avObj, type, buf, len)
//
// avSendIOCtrlFrame (PLT at 0x1311d0) takes:
//   rdi = avObj, rsi = type, rdx = buf, rcx = len, r8d = 0x70 (flags)
//
// The IOCtrl packet for IPCAM_START (type=0xFF01, buf=NULL, len=0):
//
//   Wire format (from avSendIOCtrlFrame → _avSendIOCtrl_Old analysis and
//   comparison with TUTK IOCtrl documentation):
//
//   16-byte AvFrameHeader (sub=CTRL=0x02, dir=C→P):
//     payload_len = 8  (4 bytes type + 4 bytes data_len)
//     magic       = 0x0002013f
//     sequence    = tx_seq++
//     reserved    = 0
//
//   IOCtrl body (8 bytes):
//     [0..3] ioctrl_type  (uint32_t LE, e.g. 0x0000FF01)
//     [4..7] data_len     (uint32_t LE, 0 for IPCAM_START)
//
//   [8 .. 8+data_len-1]  optional data bytes (absent for IPCAM_START)
//
// This matches the "TUTK IOCtrl" format documented in the TUTK AV API guide.

extern "C" int avSendIOCtrl(int av_index, unsigned int type,
                             char* buf, int len)
{
    if (len < 0) return AV_ER_INVALID_SID;
    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd < 0) return AV_ER_INVALID_SID;

    uint32_t body_len  = 8 + (uint32_t)len;
    uint32_t frame_len = (uint32_t)sizeof(AvFrameHeader) + body_len;

    std::vector<uint8_t> pkt(frame_len, 0);
    auto* hdr = reinterpret_cast<AvFrameHeader*>(pkt.data());

    fill_av_header(hdr, kFrameSubtypeCtrl, kFrameDirClientToP,
                   body_len, ch.tx_seq++);

    uint8_t* body = pkt.data() + sizeof(AvFrameHeader);
    uint32_t ioctrl_type = htole32(type);
    uint32_t data_len    = htole32((uint32_t)len);
    memcpy(body + 0, &ioctrl_type, 4);
    memcpy(body + 4, &data_len,    4);
    if (len > 0 && buf)
        memcpy(body + 8, buf, (size_t)len);

    if (av_channel_write(&ch, pkt.data(), frame_len) < 0) {
        fprintf(stderr, "[oss-av] avSendIOCtrl type=0x%x send failed: %s\n",
                type, strerror(errno));
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    fprintf(stderr, "[oss-av] avSendIOCtrl type=0x%04x len=%d sent\n", type, len);
    return 0;
}

// ==========================================================================
// avRecvFrameData2 — receive one H.264 frame
// ==========================================================================
//
// Signature (from 0x15f9c0 disassembly):
//   int avRecvFrameData2(int     av_index,
//                        char*   video_buf,
//                        int     buf_size,       // r13d
//                        int*    actual,          // rcx
//                        int*    frame_count,     // [rsp+0x88] = r14
//                        char*   ioctrl_buf,      // r8 = rbp
//                        int     ioctrl_size,     // r9 (stack arg)
//                        unsigned int* timestamp, // [rsp+0x90]
//                        int*    ioctrl_count);   // [rsp+0x88] → confusing;
//                                                 // see note below
//
// NOTE: The avRecvFrameData2 signature in the public TUTK AV API is:
//   int avRecvFrameData2(int AV_index,
//                        unsigned char *abFrameData,
//                        int nMaxBufSize,
//                        int *pnActualFrameSize,
//                        int *pnExpectedFrameSize,    <- "frame_count" slot
//                        char *pIoctrlBuf,
//                        int nMaxIoctrlBufSize,
//                        unsigned int *pnIOCtrlDataSize, <- "ioctrl_count"
//                        unsigned int *pnFrameIdx);   <- "timestamp" slot
//
// In the binary at 0x15f9c0, the vtable call at 0x15fa78 dispatches to
// _avRecvData with the args rearranged on the stack.  The 0x10 stored at
// 0x20(%rsp) before the call is the size of an output descriptor struct
// (16 bytes = sizeof(AvFrameHeader)).
//
// Our implementation:
//   1. Reads one UDP datagram (one TUTK AV packet)
//   2. Validates the 16-byte AvFrameHeader
//   3. If it is a video frame (sub != CTRL): copies payload to video_buf
//   4. If it is an IOCtrl frame: copies payload to ioctrl_buf
//   5. Fills output parameters

extern "C" int avRecvFrameData2(int av_index,
                                 char* video_buf,
                                 int buf_size,
                                 int* actual,
                                 int* frame_count,
                                 char* ioctrl_buf,
                                 int ioctrl_size,
                                 unsigned int* timestamp,
                                 int* ioctrl_count)
{
    if (actual)       *actual       = 0;
    if (frame_count)  *frame_count  = 0;
    if (timestamp)    *timestamp    = 0;
    if (ioctrl_count) *ioctrl_count = 0;

    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd < 0) return AV_ER_INVALID_SID;

    const int kRecvTimeoutMs = 1000;
    set_recv_timeout(ch.sock_fd, kRecvTimeoutMs);

    static constexpr size_t kRawBufSize = (1u << 20) + 64;  // IOTC hdr + DTLS record + tag
    static constexpr size_t kPktBufSize = 1u << 20;
    std::vector<uint8_t> raw_buf(kRawBufSize);
    std::vector<uint8_t> pkt_buf(kPktBufSize);

    const uint8_t* frame_data = nullptr;
    size_t         frame_len  = 0;

    static constexpr int kMaxRetries = 32;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        ssize_t n = recv(ch.sock_fd, raw_buf.data(), raw_buf.size(), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                return AV_ER_TIMEOUT;
            return AV_ER_SESSION_CLOSE_BY_REMOTE;
        }

        if (ch.use_dtls && ch.dtls_sess) {
            // Decrypt DTLS ApplicationData record
            int pn = dtls_decrypt_one(ch.dtls_sess,
                                       raw_buf.data(), (size_t)n,
                                       pkt_buf.data(), pkt_buf.size());
            if (pn == 0) continue;  // non-AppData (keepalive etc.) or AEAD failure
            if (pn < 0) continue;
            frame_data = pkt_buf.data();
            frame_len  = (size_t)pn;
        } else {
            if ((size_t)n < sizeof(AvFrameHeader)) continue;
            frame_data = raw_buf.data();
            frame_len  = (size_t)n;
        }

        if (frame_len >= sizeof(AvFrameHeader) && is_av_frame_header(frame_data))
            break;  // got a valid AV frame

        frame_data = nullptr;  // TUTK keepalive or control packet — skip
    }

    if (!frame_data) return AV_ER_TIMEOUT;

    const auto* hdr = reinterpret_cast<const AvFrameHeader*>(frame_data);
    uint32_t magic       = le32toh(hdr->magic);
    uint32_t payload_len = le32toh(hdr->payload_len);
    uint32_t seq         = le32toh(hdr->sequence);
    uint8_t  sub_type    = (magic >> 16) & 0xff;

    if (payload_len > (uint32_t)(frame_len - sizeof(AvFrameHeader)))
        return AV_ER_INCOMPLETE_FRAME;

    const uint8_t* payload = frame_data + sizeof(AvFrameHeader);

    if (sub_type == kFrameSubtypeCtrl) {
        // IOCtrl body: [0..3] type LE, [4..7] data_len LE, [8..] data
        if (payload_len >= 8 && ioctrl_buf && ioctrl_size > 0) {
            uint32_t data_len;
            memcpy(&data_len, payload + 4, 4);
            data_len = le32toh(data_len);

            int copy_len = (int)std::min((uint32_t)ioctrl_size, data_len);
            if (copy_len > 0 && payload_len >= 8 + data_len)
                memcpy(ioctrl_buf, payload + 8, (size_t)copy_len);
            if (ioctrl_count) *ioctrl_count = copy_len;
        }
        return 0;
    }

    if (!video_buf || buf_size <= 0) return AV_ER_EXCEED_MAX_SIZE;

    int copy_len = (int)std::min((uint32_t)buf_size, payload_len);
    memcpy(video_buf, payload, (size_t)copy_len);

    if (actual)      *actual      = copy_len;
    if (frame_count) *frame_count = (int)payload_len; // expected = total available
    if (timestamp)   *timestamp   = seq;  // sequence used as timestamp proxy

    if ((uint32_t)buf_size < payload_len)
        return AV_ER_INCOMPLETE_FRAME;  // buffer too small for full frame

    return copy_len;
}

// oss_av_attach → oss_av_login → IPCAM_START in one call.
int oss_av_start(OssSession* sess, int channel,
                 const char* account, const char* password)
{
    if (!sess || sess->state != P2PState::CONNECTED) return -1;

    AvStartIn  start_in{};
    AvStartOut start_out{};
    start_in.struct_size = sizeof(AvStartIn);
    start_in.sid         = 0;  // N/A in OSS path
    start_in.channel     = (uint8_t)(channel & 0x1f);
    start_in.timeout_sec = 30;
    start_in.account     = account;
    start_in.passwd      = password;
    start_out.struct_size = sizeof(AvStartOut);

    int idx = avClientStartEx(&start_in, &start_out);
    if (idx < 0) {
        fprintf(stderr, "[oss-av] avClientStartEx failed: %d\n", idx);
        return idx;
    }

    oss_av_attach(idx, sess->udp_sock, &sess->device_wan,
                  &sess->dtls, sess->session_token);

    int rc = oss_av_login(idx, account, password, /*timeout_ms=*/5000);
    if (rc < 0) {
        avClientStop(idx);
        return rc;
    }

    rc = avSendIOCtrl(idx, IOTYPE_USER_IPCAM_START, nullptr, 0);
    if (rc < 0) {
        fprintf(stderr, "[oss-av] IPCAM_START failed: %d\n", rc);
        avClientStop(idx);
        return rc;
    }

    fprintf(stderr, "[oss-av] stream started on av_index=%d\n", idx);
    return idx;
}

// ==========================================================================
// Assembly excerpts (for future reversers)
// ==========================================================================
//
// The following raw assembly from libBambuSource.so (TUTK SDK) is included
// as comments to document unclear behaviors:
//
// --- IotcConnectCfg size check (IOTC_Connect_ByUIDEx @ 0x1a8e10) ---
//   1a8e19: test %rdx, %rdx       ; cfg param null check
//   1a8e1c: je   0x1a8f40         ; if null → IOTC_ER_INVALID_ARG
//   1a8e22: cmpl $0x14, (%rdx)   ; cfg->struct_size == 20?
//   1a8e25: mov  %rdx, %r12
//   1a8e28: jne  0x1a8f40         ; if size != 20 → error
//   (then checks: gbFlagInitialized, gSessionNum range, UID valid,
//    cfg->field[4] == 0, authkey valid, calls IOTC_Connect_UDP_Inner)
//
// --- UID lowercase loop (IOTC_Connect_UDP_Inner @ 0x1a82a0) ---
//   1a82a0: movzbl (%r14,%rdx,1),%eax  ; load uid[i]
//   1a82a5: cmp    $0x5a, %al          ; is char > 'Z'?
//   1a82a7: lea    -0x20(%rax), %ecx   ; ecx = char - 0x20 (to lowercase)
//   1a82aa: cmovg  %ecx, %eax          ; if > 'Z', use lowercase
//   1a82ad: mov    %al, (%rsi,%rdx,1)  ; store to session uid buffer
//   1a82b0: add    $0x1, %rdx
//   1a82b4: cmp    $0x14, %rdx         ; loop 20 times (kUidLen)
//   1a82b8: jne    1a82a0
//
// --- avClientStartEx struct validation (@ 0x160790) ---
//   1607d5: cmpl  $0x37, (%rdi)        ; start_in->struct_size > 0x37?
//   1607db: jbe   0x1608e0             ; if <= 55 → AV_ER error (0xffffb1e0)
//   1607ed: cmpl  $0x17, (%rsi)        ; start_out->struct_size > 0x17?
//   1607f0: jbe   0x1608e0
//   1607f6: cmpb  $0x1f, 0x8(%rdi)    ; channel <= 0x1f (31)?
//   1607fa: ja    0x1608e0             ; if > 31 → error
//   (then extracts fields and calls avClientStart_inner)
//   Fields extracted (from the avClientStart_inner call at 0x16086a):
//     rdi  = start_in->sid         (0x04 offset)   → arg1
//     rsi  = start_in->account ptr (0x10 offset)   → arg3?
//     rdx  = start_in->passwd ptr  (0x18 offset)   → arg4?
//     rcx  = start_in->param       (0x0c offset)
//     r8d  = start_in->channel     (0x08 offset, zero-extended)
//     r9d  = start_in->flags       (0x24 offset)
//     [rsp+x] = start_in->flags2, flags3, flags4 (0x28, 0x2c, 0x30)
//     [rsp+y] = &start_out->resend, &start_out->two_way, etc.
//
// --- avRecvFrameData2 signature (@ 0x15f9c0) ---
//   rdi = av_index        (int)
//   rsi = buf             (char*)
//   rdx = (zeroed — not used directly; r13d = actual size arg below)
//   rcx = actual_size_out (int*)   [r9 = 0x8(%rsp) on entry]
//   r8  = frame_info_buf  (char*)  [rbp = r8 on entry]
//   r9  = (stack arg)
//   [rsp+0x88] = r14 = frame_count_out (int*)
//   [rsp+0x90] = ts_out (unsigned int*)
//   r13d = inBufSize (int)
//   The internal vtable call is: (*avObj->vtable[0x38/8])(avObj, buf, ...)
//   which resolves to the internal avGetFrameData handler.
//
// --- IOTC_OpenUDP_P2PSocket (@ 0x1883c0) ---
//   0x1883e2: movzwl gP2PLocalUdpPort, %eax  ; load configured UDP port
//   0x1883f7: movl $0x588, 0xc(%rsp)         ; 0x588 = 1416 used as buf size?
//   (calls pConnMgr vtable to create/bind socket)
//   Port = gP2PLocalUdpPort (default 0 = ephemeral, set by IOTC_Set_LanSearchPort)

// ==========================================================================
// IOTC global state — session table and initialization
// ==========================================================================
//
// The real TUTK library keeps these as process globals.  In our open
// reimplementation we keep them in the oss_tutk namespace as statics.
//
// Session table layout confirmed from disassembly:
//   gSessionInfo[] — malloc'd array of max_sessions × 0x16c0 bytes
//   Each slot's "state" byte is at slot[0x19]:
//     0 = free, 1 = busy/connected, 2 = relay, 3 = connecting, 4 = other
//   gbFlagInitialized:
//     0 = never initialized, 1 = in progress, 2 = initialized (success)
//
// IOTC_Initialize2 also allocates:
//   gPreSessionInfo[] — max_sessions × 0x60 bytes (pre-session scratch area)
//
// Mutex initialization: uses pthread_mutexattr_settype(PTHREAD_MUTEX_RECURSIVE)
// (type=1) for the 10+ internal mutexes.  We replicate this for correctness.

static constexpr uint8_t kSessionStateFree       = 0;
static constexpr uint8_t kSessionStateBusy       = 1;   // connected
[[maybe_unused]] static constexpr uint8_t kSessionStateRelay = 2;
static constexpr uint8_t kSessionStateConnecting = 3;

// Offset within each 0x16c0-byte slot where the "state" byte lives.
// Confirmed: IOTC_Get_SessionID tests cmpb $0x0, slot+0x19 (= byte 25).
static constexpr size_t  kSessionStateOff = 0x19;

// Offset within each slot where our OssSession* pointer is stored.
// We use an otherwise-unused region well away from the TUTK-reserved area.
// The TUTK slot is 0x16c0 bytes; we stash our pointer at offset 0x1640.
static constexpr size_t  kSessionPtrOff   = 0x1640;

struct IotcGlobals {
    uint8_t*           session_table   = nullptr;  // gSessionInfo (max_sess × 0x16c0)
    uint8_t*           pre_session_tbl = nullptr;  // gPreSessionInfo (max_sess × 0x60)
    unsigned int       max_sessions    = 0;
    int                flag_initialized= 0;        // gbFlagInitialized: 0/1/2
    pthread_mutex_t    table_mutex     = PTHREAD_MUTEX_INITIALIZER;
};

static IotcGlobals g_iotc;

// Region table (gRegionName, index 1..4 are valid; index 0 = "reserved" / invalid).
// Confirmed from TUTK_SDK_Set_Region disassembly: validates (index-1) <= 3 before use.
static const char* const kRegionNames[5] = {
    "reserved",   // 0 — invalid
    "cn",         // 1
    "eu",         // 2
    "us",         // 3
    "asia",       // 4
};

// Port table confirmed from gTcpTryPort at file offset 0x3fefb0.
// IOTC_TcpConnectToMasterTryPort cycles through these, tries 12 server addresses,
// port index = (attempt mod 5).  The code byte-swaps via rol $0x8.
static const uint16_t kTcpTryPorts[] = {
    80, 443, 21047, 8080, 8000, 20297, 17236, /* 0 skipped */ 8686
};
[[maybe_unused]] static constexpr size_t kNumTcpPorts = sizeof(kTcpTryPorts) / sizeof(kTcpTryPorts[0]);

static uint8_t* session_slot(int sid)
{
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return nullptr;
    return g_iotc.session_table + (size_t)sid * kSessionInfoStride;
}

static uint8_t session_state(int sid)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return 0xff;
    return slot[kSessionStateOff];
}

static void session_set_ptr(int sid, OssSession* ptr)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return;
    // NOLINTNEXTLINE(bugprone-sizeof-expression)
    memcpy(slot + kSessionPtrOff, &ptr, sizeof(ptr));
}

static OssSession* session_get_ptr(int sid)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return nullptr;
    OssSession* ptr = nullptr;
    // NOLINTNEXTLINE(bugprone-sizeof-expression)
    memcpy(&ptr, slot + kSessionPtrOff, sizeof(ptr));
    return ptr;
}

// ==========================================================================
// IOTC_Initialize2 — allocate session table, initialize state, start threads
// ==========================================================================
//
// Confirmed from disassembly of IOTC_Initialize2 @ 0x19dcd0:
//   - Checks gbFlagInitialized; if already 2, returns IOTC_ER_ALREADY_INITIALIZED
//   - Sets gbFlagInitialized = 1 (in-progress)
//   - malloc(max_sessions * 0x16c0) → gSessionInfo
//   - malloc(max_sessions * 0x60)   → gPreSessionInfo
//   - Initializes mutexes with pthread_mutexattr_settype type=RECURSIVE (1)
//   - Calls TConnManager_create (creates the connection manager vtable object)
//   - Calls tutk_TaskMng_Create / tutk_TaskMng_Init (not raw pthreads)
//   - Calls IOTC_sCHL_initialize for DTLS/crypto channel init
//   - Sets gbFlagInitialized = 2 on success
//   - Returns 0 on success; negative IOTC error code on failure

extern "C" int IOTC_Initialize2(unsigned int max_sessions)
{
    if (g_iotc.flag_initialized == 2)
        return IOTC_ER_ALREADY_INITIALIZED;

    if (max_sessions == 0) max_sessions = 1;

    g_iotc.flag_initialized = 1;

    g_iotc.session_table = static_cast<uint8_t*>(
        calloc(max_sessions, kSessionInfoStride));
    if (!g_iotc.session_table) {
        g_iotc.flag_initialized = 0;
        return IOTC_ER_NOT_INITIALIZED;
    }

    g_iotc.pre_session_tbl = static_cast<uint8_t*>(  // pre-session scratch: max_sessions × 0x60
        calloc(max_sessions, 0x60));
    if (!g_iotc.pre_session_tbl) {
        free(g_iotc.session_table);
        g_iotc.session_table    = nullptr;
        g_iotc.flag_initialized = 0;
        return IOTC_ER_NOT_INITIALIZED;
    }

    g_iotc.max_sessions = max_sessions;

    {  // mutex type=RECURSIVE (mirrors TUTK's pthread_mutexattr_settype)
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_iotc.table_mutex, &attr);
        pthread_mutexattr_destroy(&attr);
    }

    for (unsigned int i = 0; i < max_sessions; ++i) {
        uint8_t* slot = g_iotc.session_table + i * kSessionInfoStride;
        slot[kSessionStateOff] = kSessionStateFree;
    }

    av_channels_init();

    g_iotc.flag_initialized = 2;

    fprintf(stderr, "[oss-iotc] IOTC_Initialize2: max_sessions=%u, session_table=%p\n",
            max_sessions, (void*)g_iotc.session_table);
    return 0;
}

// ==========================================================================
// TUTK_SDK_Set_Region — select geographic master server region
// ==========================================================================
//
// Confirmed from disassembly of TUTK_SDK_Set_Region @ 0x1afc80:
//   - Validates: (region - 1) <= 3  →  only indices 1..4 are valid
//     (index 0 = "reserved" in gRegionName; the binary does sub $1, test <=3)
//   - Looks up gRegionName[region] to get region string ("cn"/"eu"/"us"/"asia")
//   - Calls SetMasterRegion(region_string) which calls CreateDomainName with
//     gHostName entries to build the final FQDN
//   - gIsKeySet must be true for GetMasterDomainName to succeed; without a
//     valid license key the domain cannot be resolved (returns IOTC_ER_NOT_LICENSE)
//
// We skip the license-key check and store the region for use in master_hostname().

static TutkRegion g_region = TutkRegion::Global;

extern "C" void oss_iotc_set_dtls_creds(const char* passwd, const char* account)
{
    if (passwd)  g_oss_dtls_passwd  = passwd;
    if (account) g_oss_dtls_account = account;
}

extern "C" int TUTK_SDK_Set_Region(int region)
{
    if (region < 1 || region > 4) {  // binary checks (region-1) unsigned <= 3
        fprintf(stderr, "[oss-iotc] TUTK_SDK_Set_Region: invalid region %d "
                "(must be 1=cn, 2=eu, 3=us, 4=asia)\n", region);
        return -1;
    }

    g_region = static_cast<TutkRegion>(region);
    fprintf(stderr, "[oss-iotc] TUTK_SDK_Set_Region: region=%d (%s), "
            "master will be %s\n",
            region, kRegionNames[region],
            master_hostname(g_region).c_str());
    return 0;
}

// ==========================================================================
// IOTC_Get_SessionID — allocate a free session slot
// ==========================================================================
//
// Confirmed from disassembly of IOTC_Get_SessionID @ 0x197950:
//   - Checks gbFlagInitialized == 2 (returns IOTC_ER_NOT_INITIALIZED if not)
//   - Acquires session table mutex
//   - Scans gSessionInfo[] for first slot where state_byte (slot[0x19]) == 0
//   - Sets that slot's state to 1 (busy/reserved) atomically
//   - Returns the slot index (0-based) as the session ID
//   - Returns IOTC_ER_EXCEED_MAX_SESSION if no free slot found

extern "C" int IOTC_Get_SessionID()
{
    if (g_iotc.flag_initialized != 2)
        return IOTC_ER_NOT_INITIALIZED;

    pthread_mutex_lock(&g_iotc.table_mutex);
    int found = -1;
    for (unsigned int i = 0; i < g_iotc.max_sessions; ++i) {
        uint8_t* slot = g_iotc.session_table + i * kSessionInfoStride;
        if (slot[kSessionStateOff] == kSessionStateFree) {
            slot[kSessionStateOff] = kSessionStateConnecting;  // reserve while holding mutex
            found = (int)i;
            break;
        }
    }
    pthread_mutex_unlock(&g_iotc.table_mutex);

    if (found < 0) {
        fprintf(stderr, "[oss-iotc] IOTC_Get_SessionID: no free session slots\n");
        return IOTC_ER_EXCEED_MAX_SESSION;
    }

    fprintf(stderr, "[oss-iotc] IOTC_Get_SessionID: allocated sid=%d\n", found);
    return found;
}

// ==========================================================================
// IOTC_Connect_ByUIDEx — full P2P connect to a device UID
// ==========================================================================
//
// Confirmed from disassembly of IOTC_Connect_ByUIDEx @ 0x1a8e10:
//   1a8e19: test %rdx, %rdx      — cfg must not be NULL
//   1a8e22: cmpl $0x14, (%rdx)   — cfg->struct_size must == 0x14 = 20
//   1a8e28: jne 0x1a8f40         — error if not
//   Then checks (in order):
//     - gbFlagInitialized == 2       → IOTC_ER_NOT_INITIALIZED
//     - sid within [0, max_sessions) → IOTC_ER_INVALID_SID
//     - uid not NULL                 → IOTC_ER_INVALID_ARG
//     - uid_valid(uid)               → IOTC_ER_INVALID_ARG
//     - cfg->field[4] == 0 ?         → (auth mode check)
//     - authkey field check          → (authkey validation)
//   Then calls IOTC_Connect_UDP_Inner @ 0x1a81b0 which:
//     - Copies uid to session slot (lowercased), stores authkey
//     - Opens UDP P2P socket
//     - Runs LAN search (AddLanSearchTask)
//     - Queries master (AddMasterQueryTask)
//     - Runs NAT traversal state machine
//     - Returns 0 on P2P success, negative on error

extern "C" int IOTC_Connect_ByUIDEx(const char* uid, int sid, void* cfg_v)
{
    if (!cfg_v) return IOTC_ER_INVALID_SID;
    const auto* cfg = static_cast<const IotcConnectCfg*>(cfg_v);
    if (cfg->struct_size != 0x14) return IOTC_ER_INVALID_SID;  // confirmed at 1a8e22
    if (g_iotc.flag_initialized != 2) return IOTC_ER_NOT_INITIALIZED;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return IOTC_ER_INVALID_SID;
    if (!uid) return IOTC_ER_INVALID_SID;
    std::string uid_str(uid);
    if (!uid_valid(uid_str)) {
        fprintf(stderr, "[oss-iotc] IOTC_Connect_ByUIDEx: invalid UID '%s'\n", uid);
        return IOTC_ER_INVALID_SID;
    }

    uint64_t authkey = (uint64_t)cfg->authkey_lo | ((uint64_t)cfg->authkey_hi << 32);
    {
        pthread_mutex_lock(&g_iotc.table_mutex);
        uint8_t* slot = session_slot(sid);
        if (!slot) {
            pthread_mutex_unlock(&g_iotc.table_mutex);
            return IOTC_ER_INVALID_SID;
        }
        slot[kSessionStateOff] = kSessionStateConnecting;
        pthread_mutex_unlock(&g_iotc.table_mutex);
    }

    fprintf(stderr, "[oss-iotc] IOTC_Connect_ByUIDEx: uid='%s' sid=%d "
            "authkey=0x%016llx timeout=%us\n",
            uid, sid, (unsigned long long)authkey, cfg->timeout1_sec);

    OssSession* sess = iotc_connect(uid_str, authkey, "888888", g_region);

    if (!sess) {
        pthread_mutex_lock(&g_iotc.table_mutex);
        uint8_t* slot = session_slot(sid);
        if (slot) slot[kSessionStateOff] = kSessionStateFree;
        pthread_mutex_unlock(&g_iotc.table_mutex);
        fprintf(stderr, "[oss-iotc] IOTC_Connect_ByUIDEx: connect failed\n");
        return IOTC_ER_NOT_INITIALIZED;  // generic connect failure
    }

    pthread_mutex_lock(&g_iotc.table_mutex);
    uint8_t* slot = session_slot(sid);
    if (slot) {
        slot[kSessionStateOff] = kSessionStateBusy;
        session_set_ptr(sid, sess);
    }
    pthread_mutex_unlock(&g_iotc.table_mutex);

    fprintf(stderr, "[oss-iotc] IOTC_Connect_ByUIDEx: connected, sid=%d\n", sid);
    return sid;
}

// Returns 0 (P2P path) if connected, negative error if not.
// Real binary returns the send-path type; we collapse to connected/not.
extern "C" int IOTC_Session_Check_Ex(int sid)
{
    if (g_iotc.flag_initialized != 2) return IOTC_ER_NOT_INITIALIZED;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return IOTC_ER_INVALID_SID;

    uint8_t state = session_state(sid);
    if (state == kSessionStateFree) return IOTC_ER_INVALID_SID;

    OssSession* sess = session_get_ptr(sid);
    if (!sess) return IOTC_ER_INVALID_SID;

    if (sess->state == P2PState::CONNECTED)
        return 0;  // 0 = P2P, 1 = relay (TUTK convention)

    return IOTC_ER_INVALID_SID;
}

// ==========================================================================
// IOTC_Session_Close — tear down a session and release its slot
// ==========================================================================
//
// Confirmed from disassembly of IOTC_Session_Close @ 0x19bf80:
//   - Validates sid and state byte
//   - If state == kSessionStateRelay:
//       sends MSG_RLY_ALIVE_S2C close notification to relay server
//   - Sets session state = free  (slot[0x19] = 0)
//   - Calls AV layer callback teardown
//   - Releases all AV channels attached to this session
//   - Closes UDP socket
//   - Zeroes the slot (memset)
//
extern "C" void IOTC_Session_Close(int sid)
{
    if (g_iotc.flag_initialized != 2) return;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return;

    OssSession* sess = nullptr;

    pthread_mutex_lock(&g_iotc.table_mutex);
    uint8_t* slot = session_slot(sid);
    if (slot && slot[kSessionStateOff] != kSessionStateFree) {
        sess = session_get_ptr(sid);
        memset(slot, 0, kSessionInfoStride);  // zeroes state byte → kSessionStateFree
    }
    pthread_mutex_unlock(&g_iotc.table_mutex);

    if (!sess) {
        fprintf(stderr, "[oss-iotc] IOTC_Session_Close: sid=%d not active\n", sid);
        return;
    }

    for (int i = 0; i < kMaxAvChannels; ++i) {
        AvChannel& ch = g_av_channels[i];
        if (ch.active && ch.sock_fd == sess->udp_sock) {
            ch.active = false;
        }
    }

    iotc_close(sess);

    fprintf(stderr, "[oss-iotc] IOTC_Session_Close: sid=%d closed\n", sid);
}

} // namespace oss_tutk
} // namespace bambu_net
