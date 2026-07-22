// Standalone probe for BambuSource's C ABI: dial a printer's :6000 video
// tunnel and report whether frames actually arrive. Bypasses DirectShow so a
// silent "Playing..." in the slicer can be told apart from a dead transport.
#include <windows.h>
#include <cstdio>
#include <cstring>

extern "C" {
typedef void* Bambu_Tunnel;
struct Bambu_StreamInfo {
    int                  type;
    int                  sub_type;
    union { struct { int width; int height; int frame_rate; } video;
            struct { int format; int channel_count; int sample_rate; } audio; } format;
    int                  max_frame_size;
    int                  format_size;
    unsigned char const* format_buffer;
};
struct Bambu_Sample {
    int                  itrack;
    int                  size;
    int                  flags;
    unsigned char const* buffer;
    unsigned long long   decode_time;
};
typedef void (*Logger)(void* ctx, int level, wchar_t const* msg);
}

typedef int  (*fn_Init)();
typedef int  (*fn_Create)(Bambu_Tunnel*, char const*);
typedef int  (*fn_Open)(Bambu_Tunnel);
typedef int  (*fn_StartStream)(Bambu_Tunnel, bool);
typedef int  (*fn_GetStreamCount)(Bambu_Tunnel);
typedef int  (*fn_GetStreamInfo)(Bambu_Tunnel, int, Bambu_StreamInfo*);
typedef int  (*fn_ReadSample)(Bambu_Tunnel, Bambu_Sample*);
typedef void (*fn_Close)(Bambu_Tunnel);
typedef void (*fn_Destroy)(Bambu_Tunnel);
typedef void (*fn_SetLogger)(Bambu_Tunnel, Logger, void*);

static void logcb(void*, int level, wchar_t const* msg) {
    if (msg) wprintf(L"    [bs:%d] %s\n", level, msg);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: bs_probe <bambu-url> [path-to-BambuSource.dll]\n");
        return 2;
    }
    const char* dll = (argc > 2) ? argv[2] : "BambuSource.dll";
    bool dump = (argc > 3 && argv[3][0] == 'd');
    HMODULE h = LoadLibraryA(dll);
    if (!h) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }
    printf("loaded %s\n", dll);

    auto Init   = (fn_Init)GetProcAddress(h, "Bambu_Init");
    auto Create = (fn_Create)GetProcAddress(h, "Bambu_Create");
    auto Open   = (fn_Open)GetProcAddress(h, "Bambu_Open");
    auto Start  = (fn_StartStream)GetProcAddress(h, "Bambu_StartStream");
    auto Count  = (fn_GetStreamCount)GetProcAddress(h, "Bambu_GetStreamCount");
    auto Info   = (fn_GetStreamInfo)GetProcAddress(h, "Bambu_GetStreamInfo");
    auto Read   = (fn_ReadSample)GetProcAddress(h, "Bambu_ReadSample");
    auto Close  = (fn_Close)GetProcAddress(h, "Bambu_Close");
    auto Destroy= (fn_Destroy)GetProcAddress(h, "Bambu_Destroy");
    auto SetLog = (fn_SetLogger)GetProcAddress(h, "Bambu_SetLogger");
    if (!Create || !Open || !Read) { printf("missing exports\n"); return 1; }

    if (Init) printf("Bambu_Init -> %d\n", Init());

    Bambu_Tunnel t = nullptr;
    int rc = Create(&t, argv[1]);
    printf("Bambu_Create -> %d (tunnel=%p)\n", rc, t);
    if (rc != 0 || !t) return 1;
    if (SetLog) SetLog(t, logcb, nullptr);

    rc = Open(t);
    printf("Bambu_Open -> %d\n", rc);
    if (rc != 0) { Destroy(t); return 1; }

    if (Start) printf("Bambu_StartStream -> %d\n", Start(t, true));
    if (Count) {
        int n = Count(t);
        printf("streams: %d\n", n);
        for (int i = 0; i < n && Info; i++) {
            Bambu_StreamInfo si; memset(&si, 0, sizeof si);
            if (Info(t, i, &si) == 0)
                printf("  stream %d: type=%d %dx%d @%d\n", i, si.type,
                       si.format.video.width, si.format.video.height,
                       si.format.video.frame_rate);
        }
    }

    printf("reading samples for 15s...\n");
    DWORD t0 = GetTickCount();
    long long bytes = 0; int frames = 0, errs = 0;
    while (GetTickCount() - t0 < 15000) {
        Bambu_Sample s; memset(&s, 0, sizeof s);
        int r = Read(t, &s);
        if (r == 0) {
            frames++; bytes += s.size;
            if (dump && frames <= 3 && s.buffer && s.size > 4) {
                char fn[64]; snprintf(fn, sizeof fn, "frame_%d.jpg", frames);
                FILE* f = fopen(fn, "wb");
                if (f) { fwrite(s.buffer, 1, s.size, f); fclose(f);
                    printf("  wrote %s (%d bytes, first=%02x %02x last=%02x %02x)\n",
                           fn, s.size, s.buffer[0], s.buffer[1],
                           s.buffer[s.size-2], s.buffer[s.size-1]); }
            }
        }
        else { errs++; Sleep(20); }
    }
    printf("RESULT: frames=%d bytes=%lld errors=%d\n", frames, bytes, errs);
    if (Close) Close(t);
    if (Destroy) Destroy(t);
    return frames > 0 ? 0 : 3;
}
