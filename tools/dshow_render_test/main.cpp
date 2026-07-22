// Replicates what wxMediaCtrl does: build a DirectShow graph from our BambuSource
// filter via Intelligent Connect (source -> [MJPEG decoder] -> renderer) and grab
// the RENDERED RGB via a SampleGrabber. Proves whether the filter's output
// actually decodes+renders, independent of Orca's UI. Saves the first frame to BMP.
#include <windows.h>
#include <dshow.h>
#include <cstdio>
#include <vector>
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ISampleGrabber / callback (from qedit.h, declared here to avoid SDK dependency)
struct __declspec(uuid("6B652FFF-11FE-4fce-92AD-0266B5D7C78F")) ISampleGrabber;
struct __declspec(uuid("0579154A-2B53-4994-B0D0-E773148EFF85")) ISampleGrabberCB;
static const GUID CLSID_SampleGrabber = {0xC1F400A0,0x3F08,0x11D3,{0x9F,0x0B,0x00,0x60,0x08,0x03,0x9E,0x37}};
static const GUID CLSID_NullRenderer  = {0xC1F400A4,0x3F08,0x11D3,{0x9F,0x0B,0x00,0x60,0x08,0x03,0x9E,0x37}};

MIDL_INTERFACE("0579154A-2B53-4994-B0D0-E773148EFF85")
ISampleGrabberCB : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE SampleCB(double, IMediaSample*) = 0;
    virtual HRESULT STDMETHODCALLTYPE BufferCB(double, BYTE*, long) = 0;
};
MIDL_INTERFACE("6B652FFF-11FE-4fce-92AD-0266B5D7C78F")
ISampleGrabber : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE SetOneShot(BOOL) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetMediaType(const AM_MEDIA_TYPE*) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetConnectedMediaType(AM_MEDIA_TYPE*) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetBufferSamples(BOOL) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentBuffer(long*, long*) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentSample(IMediaSample**) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCallback(ISampleGrabberCB*, long) = 0;
};

static const GUID CLSID_BambuSource = {0x233E64FB,0x2041,0x4A6C,{0xAF,0xAB,0xFF,0x9B,0xCF,0x83,0xE7,0xAA}};

int g_w=0,g_h=0; volatile long g_frames=0; std::vector<BYTE> g_buf;

struct GrabCB : ISampleGrabberCB {
    long ref=1;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r, void** p) override {
        if (r==IID_IUnknown || r==__uuidof(ISampleGrabberCB)) { *p=this; return S_OK; } return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++ref; }
    ULONG STDMETHODCALLTYPE Release() override { return --ref; }
    HRESULT STDMETHODCALLTYPE SampleCB(double, IMediaSample* s) override {
        BYTE* d=nullptr; s->GetPointer(&d); long n=s->GetActualDataLength();
        if (d && n>0 && g_frames==0) { g_buf.assign(d, d+n);
            printf("  grabbed frame: %ld bytes\n", n); }
        InterlockedIncrement(&g_frames); return S_OK; }
    HRESULT STDMETHODCALLTYPE BufferCB(double, BYTE*, long) override { return S_OK; }
};

static void listFilters(IGraphBuilder* g) {
    IEnumFilters* e=nullptr; if (FAILED(g->EnumFilters(&e))) return;
    IBaseFilter* f=nullptr;
    printf("  graph filters: ");
    while (e->Next(1,&f,nullptr)==S_OK) { FILTER_INFO fi={}; f->QueryFilterInfo(&fi);
        wprintf(L"[%s] ", fi.achName); if (fi.pGraph) fi.pGraph->Release(); f->Release(); }
    printf("\n"); e->Release();
}

int main(int argc, char** argv) {
    const char* url = argc>1 ? argv[1] : "bambu:///local/192.168.1.116?port=6000&user=bblp&passwd=590758eb&device=03900D610219434";
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    IGraphBuilder* graph=nullptr;
    CoCreateInstance(CLSID_FilterGraph,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&graph));

    // our source
    IBaseFilter* src=nullptr;
    HRESULT hr=CoCreateInstance(CLSID_BambuSource,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&src));
    if (FAILED(hr)) { printf("create BambuSource hr=0x%08lx\n",hr); return 1; }
    IFileSourceFilter* fsf=nullptr; src->QueryInterface(IID_PPV_ARGS(&fsf));
    wchar_t wurl[1024]; MultiByteToWideChar(CP_UTF8,0,url,-1,wurl,1024);
    hr=fsf->Load(wurl,nullptr); printf("Load hr=0x%08lx\n",hr);
    graph->AddFilter(src,L"BambuSource");

    // sample grabber (RGB24)
    IBaseFilter* grabF=nullptr; CoCreateInstance(CLSID_SampleGrabber,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&grabF));
    ISampleGrabber* grab=nullptr; grabF->QueryInterface(IID_PPV_ARGS(&grab));
    AM_MEDIA_TYPE gmt={}; gmt.majortype=MEDIATYPE_Video; gmt.subtype=MEDIASUBTYPE_RGB24; gmt.formattype=FORMAT_VideoInfo;
    grab->SetMediaType(&gmt); grab->SetBufferSamples(FALSE);
    GrabCB cb; grab->SetCallback(&cb,0);
    graph->AddFilter(grabF,L"Grabber");

    IBaseFilter* nullF=nullptr; CoCreateInstance(CLSID_NullRenderer,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&nullF));
    graph->AddFilter(nullF,L"NullRenderer");

    // find source out pin, render source->grabber->null via Intelligent Connect
    ICaptureGraphBuilder2* cap=nullptr;
    CoCreateInstance(CLSID_CaptureGraphBuilder2,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&cap));
    cap->SetFiltergraph(graph);
    hr=cap->RenderStream(nullptr,&MEDIATYPE_Video,src,grabF,nullF);
    printf("RenderStream hr=0x%08lx  %s\n",hr, SUCCEEDED(hr)?"(decode+render path BUILT)":"(FAILED to build path)");
    listFilters(graph);

    if (SUCCEEDED(hr)) {
        AM_MEDIA_TYPE cmt={}; if (SUCCEEDED(grab->GetConnectedMediaType(&cmt)) && cmt.pbFormat) {
            auto* vih=(VIDEOINFOHEADER*)cmt.pbFormat; g_w=vih->bmiHeader.biWidth; g_h=abs(vih->bmiHeader.biHeight);
            printf("  grabber connected at %dx%d\n", g_w, g_h); }
        IMediaControl* mc=nullptr; graph->QueryInterface(IID_PPV_ARGS(&mc));
        mc->Run();
        for (int i=0;i<50 && g_frames<3;i++) Sleep(200);
        printf("frames rendered: %ld\n", g_frames);
        mc->Stop(); mc->Release();
        if (!g_buf.empty() && g_w>0) {
            unsigned long long sum=0; for (size_t k=0;k<g_buf.size();k++) sum+=g_buf[k];
            printf("avg pixel value: %.1f\n", (double)sum/g_buf.size());
            // write BMP (RGB24)
            BITMAPFILEHEADER bf={}; BITMAPINFOHEADER bi={};
            bf.bfType=0x4D42; bf.bfOffBits=sizeof(bf)+sizeof(bi); bf.bfSize=bf.bfOffBits+(DWORD)g_buf.size();
            bi.biSize=sizeof(bi); bi.biWidth=g_w; bi.biHeight=g_h; bi.biPlanes=1; bi.biBitCount=24; bi.biCompression=BI_RGB; bi.biSizeImage=(DWORD)g_buf.size();
            FILE* o=fopen("rendered.bmp","wb"); fwrite(&bf,sizeof(bf),1,o); fwrite(&bi,sizeof(bi),1,o); fwrite(g_buf.data(),1,g_buf.size(),o); fclose(o);
            printf("wrote rendered.bmp\n");
        }
    }
    CoUninitialize();
    return g_frames>0 ? 0 : 3;
}
