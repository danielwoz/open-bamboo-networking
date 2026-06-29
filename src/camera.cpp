// SPDX-License-Identifier: AGPL-3.0-only
//
// JPEG camera streaming for A1/A1 mini/N1/N2S/P1S/P1P/C13/C14 printers.
//
// These printers expose a TLS MJPEG stream on TCP port 6000.  After the TLS
// handshake we send an 80-byte auth packet, then read 16-byte frame headers
// followed by raw JPEG payloads in a loop.  The frames are pushed into a
// shared FrameQueue that is drained by a per-session MJPEG HTTP server
// listening on a loopback ephemeral port.  Studio's wxMediaCtrl is given the
// http://127.0.0.1:PORT/cam URL and consumes the multipart/x-mixed-replace
// stream natively.
//
// Wire protocol (binary, same as BambuStudio-bridge reference):
//   Auth packet (80 bytes, sent once after TLS):
//     [0..3]  u32 LE payload size = 0x40
//     [4..7]  u32 LE type         = 0x3000
//     [8..15] u64 zero (flags + reserved)
//     [16..47] username "bblp" NUL-padded to 32 bytes
//     [48..79] LAN access code NUL-padded to 32 bytes
//   Frame header (16 bytes LE) followed by JPEG payload:
//     [0..3]  u32 payload size
//     [4..7]  u32 itrack (0)
//     [8..11] u32 flags  (1)
//     [12..15] u32 reserved

#include "obn/camera.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace obn::camera {

namespace {

// ── wire protocol constants ──────────────────────────────────────────────────

constexpr uint32_t    kAuthPayloadSize = 0x40;
constexpr uint32_t    kAuthTypeJpeg    = 0x3000;
constexpr std::size_t kAuthPacketLen   = 80;
constexpr std::size_t kFrameHeaderLen  = 16;
constexpr uint8_t     kJpegSoi[2]      = {0xFF, 0xD8};
constexpr uint32_t    kMaxPayloadBytes = 8u * 1024u * 1024u;

// ── little-endian helpers ────────────────────────────────────────────────────

void write_u32_le(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v);
    out[1] = static_cast<uint8_t>(v >> 8);
    out[2] = static_cast<uint8_t>(v >> 16);
    out[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t read_u32_le(const uint8_t* in) {
    return  static_cast<uint32_t>(in[0])
         | (static_cast<uint32_t>(in[1]) <<  8)
         | (static_cast<uint32_t>(in[2]) << 16)
         | (static_cast<uint32_t>(in[3]) << 24);
}

std::string to_upper(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

// ── socket send helpers ──────────────────────────────────────────────────────

bool send_raw(obn::os::socket_t fd, const void* data, std::size_t n) {
    const char* p = static_cast<const char*>(data);
    std::size_t off = 0;
    while (off < n) {
#if defined(_WIN32)
        int sent = ::send(static_cast<SOCKET>(fd), p + off,
                          static_cast<int>(n - off), 0);
#else
        ssize_t sent = ::send(static_cast<int>(fd), p + off, n - off, 0);
#endif
        if (sent <= 0) return false;
        off += static_cast<std::size_t>(sent);
    }
    return true;
}

bool send_str(obn::os::socket_t fd, const std::string& s) {
    return send_raw(fd, s.data(), s.size());
}

bool send_vec(obn::os::socket_t fd, const std::vector<uint8_t>& v) {
    return send_raw(fd, v.data(), v.size());
}

// ── TCP connect helper ───────────────────────────────────────────────────────

// Returns a connected socket (as int for OpenSSL compatibility), or -1.
int tcp_connect_to(const std::string& host, int port, int timeout_ms) {
    obn::os::winsock_init_once();

    addrinfo hints{};
    addrinfo* res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%d", port);
    if (::getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res)
        return -1;

    obn::os::socket_t best = obn::os::kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
#if defined(_WIN32)
        obn::os::socket_t fd = static_cast<obn::os::socket_t>(
            ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
#else
        obn::os::socket_t fd = ::socket(ai->ai_family,
                                         ai->ai_socktype, ai->ai_protocol);
#endif
        if (!obn::os::socket_valid(fd)) continue;

        {
            int yes = 1;
#if defined(_WIN32)
            ::setsockopt(static_cast<SOCKET>(fd), IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
            ::setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
                         &yes, sizeof(yes));
#endif
        }
        obn::os::set_nonblocking(fd);

#if defined(_WIN32)
        int rc = ::connect(static_cast<SOCKET>(fd), ai->ai_addr,
                           static_cast<int>(ai->ai_addrlen));
#else
        int rc = ::connect(static_cast<int>(fd), ai->ai_addr, ai->ai_addrlen);
#endif
        if (rc == 0) { best = fd; break; }

        int err = obn::os::last_socket_error();
        if (obn::os::socket_in_progress(err)) {
            short rev = 0;
            int pr = obn::os::poll_one(fd, POLLOUT, timeout_ms, &rev);
            if (pr > 0 && (rev & POLLOUT)) {
                int so_err = 0;
#if defined(_WIN32)
                int sl = sizeof(so_err);
                ::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&so_err), &sl);
#else
                socklen_t sl = sizeof(so_err);
                ::getsockopt(static_cast<int>(fd), SOL_SOCKET, SO_ERROR,
                             &so_err, &sl);
#endif
                if (so_err == 0) { best = fd; break; }
            }
        }
        obn::os::close_socket(fd);
    }
    ::freeaddrinfo(res);
    return obn::os::socket_valid(best) ? static_cast<int>(best) : -1;
}

// ── FrameQueue ───────────────────────────────────────────────────────────────
//
// Thread-safe circular buffer shared between JpegCameraSource (producer) and
// MjpegServer's per-client handler threads (consumers).  Older frames are
// silently dropped once the queue reaches kMaxFrames so a slow client never
// stalls the capture thread.

class FrameQueue {
public:
    static constexpr int kMaxFrames = 10;

    void push(std::vector<uint8_t> frame) {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        while (static_cast<int>(frames_.size()) >= kMaxFrames)
            frames_.pop_front();
        frames_.push_back(std::move(frame));
        cv_.notify_one();
    }

    // Blocks up to timeout_ms.  Returns true + fills `out` on success.
    // Returns false on timeout or if the queue has been closed.
    bool pop(std::vector<uint8_t>& out, int timeout_ms) {
        std::unique_lock<std::mutex> lk(mu_);
        bool ready = cv_.wait_for(
            lk, std::chrono::milliseconds(timeout_ms),
            [this]{ return !frames_.empty() || closed_; });
        if (!ready || frames_.empty()) return false;
        out = std::move(frames_.front());
        frames_.pop_front();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
        frames_.clear();
        cv_.notify_all();
    }

    bool closed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_;
    }

private:
    mutable std::mutex               mu_;
    std::condition_variable          cv_;
    std::deque<std::vector<uint8_t>> frames_;
    bool                             closed_ = false;
};

// ── JpegCameraSource ─────────────────────────────────────────────────────────
//
// Maintains a TLS 1.2 connection to the printer's port 6000, reads binary-
// framed JPEG data in a background thread, and pushes each frame into the
// shared FrameQueue.
//
// Thread model
//   reader_thread_   creates, uses, and frees ssl_ / ssl_ctx_.
//   stop() / mu_     protects fd_ so that stop() can close the underlying
//                    socket to interrupt any blocking SSL_read without
//                    touching ssl_ from a foreign thread.  After join() the
//                    reader thread has fully cleaned up ssl_.

class JpegCameraSource {
public:
    explicit JpegCameraSource(const JpegConfig& cfg,
                              std::shared_ptr<FrameQueue> queue)
        : cfg_(cfg), queue_(std::move(queue)) {}

    ~JpegCameraSource() { stop(); }

    JpegCameraSource(const JpegCameraSource&)            = delete;
    JpegCameraSource& operator=(const JpegCameraSource&) = delete;

    void start() {
        running_.store(true);
        reader_thread_ = std::thread(&JpegCameraSource::reader_loop_, this);
    }

    void stop() {
        running_.store(false);
        {
            std::lock_guard<std::mutex> lk(mu_);
            close_fd_locked_();
        }
        if (reader_thread_.joinable()) reader_thread_.join();
    }

private:
    // ── reader thread ─────────────────────────────────────────────────────

    void reader_loop_() {
        while (running_.load()) {
            try {
                if (!connect_and_auth_()) {
                    // back off before retry
                    for (int i = 0; i < 30 && running_.load(); ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                OBN_INFO("camera: %s port-6000 connected", cfg_.dev_id.c_str());
                read_frames_();
                OBN_INFO("camera: %s stream ended", cfg_.dev_id.c_str());
            } catch (...) {
                OBN_WARN("camera: %s reader exception", cfg_.dev_id.c_str());
            }
            cleanup_tls_();
        }
        cleanup_tls_();
        queue_->close();
    }

    // Connects + TLS + auth.  Sets fd_ (under mu_) and ssl_/ssl_ctx_
    // (reader-thread-only).  Returns true on full success.
    bool connect_and_auth_() {
        int fd = tcp_connect_to(cfg_.ip, cfg_.port, cfg_.connect_timeout_ms);
        if (fd < 0) {
            OBN_WARN("camera: %s tcp_connect %s:%d failed",
                     cfg_.dev_id.c_str(), cfg_.ip.c_str(), cfg_.port);
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_.load()) {
                obn::os::close_socket(static_cast<obn::os::socket_t>(fd));
                return false;
            }
            fd_ = fd;
        }

        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx_) { cleanup_tls_(); return false; }
        SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_2_VERSION);
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_cipher_list(ssl_ctx_, "AES256-GCM-SHA384");

        ssl_ = SSL_new(ssl_ctx_);
        if (!ssl_) { cleanup_tls_(); return false; }
        SSL_set_fd(ssl_, fd_);

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(cfg_.connect_timeout_ms);
        while (true) {
            if (!running_.load()) { cleanup_tls_(); return false; }
            int r = SSL_connect(ssl_);
            if (r == 1) break;
            int e = SSL_get_error(ssl_, r);
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { cleanup_tls_(); return false; }
            int rem = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count());
            if (e == SSL_ERROR_WANT_READ) {
                if (poll_read_(rem) <= 0) { cleanup_tls_(); return false; }
            } else if (e == SSL_ERROR_WANT_WRITE) {
                if (poll_write_(rem) <= 0) { cleanup_tls_(); return false; }
            } else {
                OBN_WARN("camera: %s TLS error %d", cfg_.dev_id.c_str(), e);
                cleanup_tls_(); return false;
            }
        }

        // Build 80-byte auth packet
        std::vector<uint8_t> pkt(kAuthPacketLen, 0);
        write_u32_le(&pkt[0], kAuthPayloadSize);
        write_u32_le(&pkt[4], kAuthTypeJpeg);
        std::memcpy(&pkt[16], "bblp", 4);
        std::size_t pass_n = std::min<std::size_t>(32, cfg_.access_code.size());
        std::memcpy(&pkt[48], cfg_.access_code.data(), pass_n);
        if (ssl_write_full_(pkt.data(), pkt.size(), cfg_.connect_timeout_ms) != 0) {
            OBN_WARN("camera: %s auth write failed", cfg_.dev_id.c_str());
            cleanup_tls_(); return false;
        }
        return true;
    }

    void read_frames_() {
        std::vector<uint8_t> scratch;
        scratch.reserve(256 * 1024);
        while (running_.load()) {
            uint8_t hdr[kFrameHeaderLen];
            if (ssl_read_full_(hdr, kFrameHeaderLen, cfg_.read_timeout_ms) != 0)
                break;
            uint32_t payload = read_u32_le(hdr);
            if (payload == 0 || payload > kMaxPayloadBytes) {
                OBN_WARN("camera: %s bad payload=%u",
                         cfg_.dev_id.c_str(), payload);
                break;
            }
            if (scratch.size() < payload) scratch.resize(payload);
            if (ssl_read_full_(scratch.data(), payload, cfg_.read_timeout_ms) != 0)
                break;
            if (payload < 2 ||
                scratch[0] != kJpegSoi[0] ||
                scratch[1] != kJpegSoi[1]) {
                OBN_WARN("camera: %s frame missing SOI", cfg_.dev_id.c_str());
                break;
            }
            queue_->push(std::vector<uint8_t>(scratch.begin(),
                                              scratch.begin() + payload));
        }
    }

    // ── TLS I/O (reader thread only) ─────────────────────────────────────

    int ssl_read_full_(uint8_t* dst, std::size_t n, int timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeout_ms);
        std::size_t off = 0;
        while (off < n) {
            if (!running_.load()) return -1;
            int r = SSL_read(ssl_, dst + off, static_cast<int>(n - off));
            if (r > 0) { off += static_cast<std::size_t>(r); continue; }
            int e = SSL_get_error(ssl_, r);
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return -1;
            int rem = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count());
            if (e == SSL_ERROR_WANT_READ) {
                if (poll_read_(rem) <= 0) return -1;
            } else if (e == SSL_ERROR_WANT_WRITE) {
                if (poll_write_(rem) <= 0) return -1;
            } else {
                return -1;
            }
        }
        return 0;
    }

    int ssl_write_full_(const uint8_t* src, std::size_t n, int timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeout_ms);
        std::size_t off = 0;
        while (off < n) {
            int r = SSL_write(ssl_, src + off, static_cast<int>(n - off));
            if (r > 0) { off += static_cast<std::size_t>(r); continue; }
            int e = SSL_get_error(ssl_, r);
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return -1;
            int rem = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count());
            if (e == SSL_ERROR_WANT_READ) {
                if (poll_read_(rem) <= 0) return -1;
            } else if (e == SSL_ERROR_WANT_WRITE) {
                if (poll_write_(rem) <= 0) return -1;
            } else {
                return -1;
            }
        }
        return 0;
    }

    int poll_read_(int timeout_ms) {
        int fd; { std::lock_guard<std::mutex> lk(mu_); fd = fd_; }
        if (fd < 0) return -1;
        short rev = 0;
        return obn::os::poll_one(static_cast<obn::os::socket_t>(fd),
                                 POLLIN, timeout_ms, &rev);
    }

    int poll_write_(int timeout_ms) {
        int fd; { std::lock_guard<std::mutex> lk(mu_); fd = fd_; }
        if (fd < 0) return -1;
        short rev = 0;
        return obn::os::poll_one(static_cast<obn::os::socket_t>(fd),
                                 POLLOUT, timeout_ms, &rev);
    }

    // Closes the raw socket (under mu_).  Does NOT touch ssl_.
    void close_fd_locked_() {
        if (fd_ >= 0) {
            obn::os::close_socket(static_cast<obn::os::socket_t>(fd_));
            fd_ = -1;
        }
    }

    // Frees ssl_/ssl_ctx_ and closes the socket.  Only called on the reader
    // thread (or after join in the destructor path).
    void cleanup_tls_() {
        if (ssl_) {
            SSL_set_shutdown(ssl_, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
        std::lock_guard<std::mutex> lk(mu_);
        close_fd_locked_();
    }

    // ── members ──

    JpegConfig                  cfg_;
    std::shared_ptr<FrameQueue> queue_;

    mutable std::mutex          mu_;      // guards fd_
    int                         fd_      = -1;       // protected by mu_
    SSL_CTX*                    ssl_ctx_ = nullptr;  // reader_thread_ only
    SSL*                        ssl_     = nullptr;   // reader_thread_ only
    std::atomic<bool>           running_{false};
    std::thread                 reader_thread_;
};

// ── MjpegServer ──────────────────────────────────────────────────────────────
//
// Listens on 127.0.0.1:0 and serves a multipart/x-mixed-replace MJPEG stream
// to whatever wxMediaCtrl connects to the URL we hand Studio.  One client at a
// time is served on a short-lived detached thread.  The same FrameQueue
// shared with JpegCameraSource delivers the frames; when the queue is closed
// (because the printer disconnected) the client thread exits naturally.

class MjpegServer {
public:
    MjpegServer() = default;
    ~MjpegServer() { stop(); }

    MjpegServer(const MjpegServer&)            = delete;
    MjpegServer& operator=(const MjpegServer&) = delete;

    // Binds an ephemeral loopback port and starts the accept loop.
    // Returns the bound port on success, -1 on failure.
    int start(std::shared_ptr<FrameQueue> queue) {
        obn::os::winsock_init_once();
        queue_ = std::move(queue);

#if defined(_WIN32)
        obn::os::socket_t fd = static_cast<obn::os::socket_t>(
            ::socket(AF_INET, SOCK_STREAM, 0));
#else
        obn::os::socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (!obn::os::socket_valid(fd)) return -1;

        {
            int on = 1;
#if defined(_WIN32)
            ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_REUSEADDR,
                         reinterpret_cast<const char*>(&on), sizeof(on));
#else
            ::setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_REUSEADDR,
                         &on, sizeof(on));
#endif
        }

        sockaddr_in sa{};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port        = 0;

#if defined(_WIN32)
        if (::bind(static_cast<SOCKET>(fd),
                   reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
            ::listen(static_cast<SOCKET>(fd), 4) != 0) {
            obn::os::close_socket(fd); return -1;
        }
        int sl = sizeof(sa);
        if (::getsockname(static_cast<SOCKET>(fd),
                          reinterpret_cast<sockaddr*>(&sa), &sl) != 0) {
            obn::os::close_socket(fd); return -1;
        }
#else
        if (::bind(static_cast<int>(fd),
                   reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
            ::listen(static_cast<int>(fd), 4) != 0) {
            obn::os::close_socket(fd); return -1;
        }
        socklen_t sl = sizeof(sa);
        if (::getsockname(static_cast<int>(fd),
                          reinterpret_cast<sockaddr*>(&sa), &sl) != 0) {
            obn::os::close_socket(fd); return -1;
        }
#endif

        listen_fd_ = static_cast<std::uintptr_t>(fd);
        port_      = ntohs(sa.sin_port);
        running_.store(true);
        accept_thread_ = std::thread(&MjpegServer::accept_loop_, this);
        OBN_INFO("camera: MJPEG HTTP server on 127.0.0.1:%d", port_);
        return port_;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        auto fd = static_cast<obn::os::socket_t>(listen_fd_);
        listen_fd_ = static_cast<std::uintptr_t>(obn::os::kInvalidSocket);
        if (obn::os::socket_valid(fd)) {
            obn::os::shutdown_both(fd);
            obn::os::close_socket(fd);
        }
        if (accept_thread_.joinable()) accept_thread_.join();
    }

    int port() const { return port_; }

private:
    void accept_loop_() {
        while (running_.load()) {
            sockaddr_in ca{};
#if defined(_WIN32)
            int cl = sizeof(ca);
            obn::os::socket_t c = static_cast<obn::os::socket_t>(
                ::accept(static_cast<SOCKET>(listen_fd_),
                         reinterpret_cast<sockaddr*>(&ca), &cl));
#else
            socklen_t cl = sizeof(ca);
            obn::os::socket_t c = ::accept(
                static_cast<int>(listen_fd_),
                reinterpret_cast<sockaddr*>(&ca), &cl);
#endif
            if (!obn::os::socket_valid(c)) {
                if (!running_.load()) break;
                if (obn::os::last_socket_error() == EINTR) continue;
                break;
            }
            auto q = queue_; // shared_ptr copy for the detached thread
            std::thread([c, q]() mutable {
                serve_client_(c, std::move(q));
                obn::os::close_socket(c);
            }).detach();
        }
    }

    // Serves one MJPEG client.  Runs on a detached thread; holds its own
    // shared_ptr to the queue so the queue stays alive until the thread exits.
    static void serve_client_(obn::os::socket_t fd,
                              std::shared_ptr<FrameQueue> queue) {
        // Drain the HTTP request headers (we don't inspect them).
        char req[4096];
        std::size_t got = 0;
        while (got < sizeof(req) - 1) {
#if defined(_WIN32)
            int n = ::recv(static_cast<SOCKET>(fd), req + got,
                           static_cast<int>(sizeof(req) - 1 - got), 0);
#else
            ssize_t n = ::recv(static_cast<int>(fd), req + got,
                               sizeof(req) - 1 - got, 0);
#endif
            if (n <= 0) return;
            got += static_cast<std::size_t>(n);
            req[got] = '\0';
            if (std::strstr(req, "\r\n\r\n")) break;
        }

        // Send the multipart stream header.
        const std::string stream_hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: multipart/x-mixed-replace; boundary=frame\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n";
        if (!send_str(fd, stream_hdr)) return;

        // Push frames until the client disconnects or the queue is closed.
        while (true) {
            std::vector<uint8_t> frame;
            if (!queue->pop(frame, 2000)) {
                if (queue->closed()) break;
                continue; // timeout - try again
            }
            std::string part_hdr =
                "--frame\r\n"
                "Content-Type: image/jpeg\r\n"
                "Content-Length: " + std::to_string(frame.size()) + "\r\n"
                "\r\n";
            if (!send_str(fd, part_hdr)) break;
            if (!send_vec(fd, frame))    break;
            if (!send_str(fd, "\r\n"))   break;
        }
    }

    std::shared_ptr<FrameQueue> queue_;
    // Stored as uintptr_t to avoid dragging <winsock2.h> into header
    // (same pattern as cover_server.hpp).
    std::uintptr_t              listen_fd_{static_cast<std::uintptr_t>(-1)};
    int                         port_{0};
    std::atomic<bool>           running_{false};
    std::thread                 accept_thread_;
};

// ── CameraRegistry ───────────────────────────────────────────────────────────

struct CameraEntry {
    std::shared_ptr<FrameQueue>       queue;
    std::unique_ptr<JpegCameraSource> source;
    std::unique_ptr<MjpegServer>      server;
    std::string                       url;
};

class CameraRegistry {
public:
    static CameraRegistry& instance() {
        static CameraRegistry inst;
        return inst;
    }

    std::string start(const JpegConfig& cfg) {
        stop(cfg.dev_id); // tear down any prior session first

        auto queue  = std::make_shared<FrameQueue>();
        auto source = std::make_unique<JpegCameraSource>(cfg, queue);
        auto server = std::make_unique<MjpegServer>();

        int port = server->start(queue);
        if (port < 0) {
            OBN_ERROR("camera: MJPEG server bind failed for %s",
                      cfg.dev_id.c_str());
            return {};
        }
        source->start();

        std::string url = "http://127.0.0.1:" + std::to_string(port) + "/cam";
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto& e  = entries_[cfg.dev_id];
            e.queue  = std::move(queue);
            e.source = std::move(source);
            e.server = std::move(server);
            e.url    = url;
        }
        OBN_INFO("camera: session %s → %s", cfg.dev_id.c_str(), url.c_str());
        return url;
    }

    void stop(const std::string& dev_id) {
        std::unique_ptr<JpegCameraSource> source;
        std::unique_ptr<MjpegServer>      server;
        std::shared_ptr<FrameQueue>       queue;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = entries_.find(dev_id);
            if (it == entries_.end()) return;
            source = std::move(it->second.source);
            server = std::move(it->second.server);
            queue  = std::move(it->second.queue);
            entries_.erase(it);
        }
        // Destroy outside the lock so stop() can log and join threads.
        // source->stop() sets running_=false, closes the socket (interrupting
        // SSL_read), and joins the reader thread.  The reader thread calls
        // queue->close() just before it exits, which unblocks any in-progress
        // serve_client_ pop() so those detached threads also exit cleanly.
        if (source) source->stop();
        if (server) server->stop();
    }

    std::string get_url(const std::string& dev_id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = entries_.find(dev_id);
        return it != entries_.end() ? it->second.url : std::string{};
    }

private:
    CameraRegistry() = default;

    std::mutex                         mu_;
    std::map<std::string, CameraEntry> entries_;
};

} // namespace (anonymous)

// ── Public API ───────────────────────────────────────────────────────────────

bool is_jpeg_model(const std::string& model) {
    if (model.empty()) return false;
    const std::string up = to_upper(model);
    // Exclude X1 / H2 families — use native H.264 LAN branch instead.
    if (up.find("X1")  != std::string::npos) return false;
    if (up.find("H2")  != std::string::npos) return false;
    // Exclude legacy C-series without port-6000 streams.
    if (up.find("C11") != std::string::npos) return false;
    if (up.find("C12") != std::string::npos) return false;
    if (up.find("C16") != std::string::npos) return false;
    if (up.find("C18") != std::string::npos) return false;
    // Confirmed JPEG-capable models.
    if (up.find("A1")  != std::string::npos) return true;
    if (up.find("N1")  != std::string::npos) return true;
    if (up.find("N2S") != std::string::npos) return true;
    if (up.find("P1")  != std::string::npos) return true;
    if (up.find("C13") != std::string::npos) return true;
    if (up.find("C14") != std::string::npos) return true;
    return false;
}

std::string start_camera(const JpegConfig& cfg) {
    return CameraRegistry::instance().start(cfg);
}

void stop_camera(const std::string& dev_id) {
    CameraRegistry::instance().stop(dev_id);
}

std::string get_url(const std::string& dev_id) {
    return CameraRegistry::instance().get_url(dev_id);
}

} // namespace obn::camera
