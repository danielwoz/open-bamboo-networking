// Emits a one-line load banner to stderr (and to the log file once it is
// open) when libbambu_networking is mapped into the process. Runs outside
// the normal OBN_* log level gate so bug reports always carry a build id.

#include "obn/log.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace {

void emit_once()
{
    obn::log::emit_plugin_load_banner();
}

} // namespace

#if defined(_WIN32)

extern "C" BOOL WINAPI DllMain(HINSTANCE /*hinst*/, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
        emit_once();
    return TRUE;
}

#else

__attribute__((constructor))
static void obn_plugin_load_banner_ctor()
{
    emit_once();
}

#endif
