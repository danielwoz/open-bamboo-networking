# Vendored PThreads4W (pthreads-win32 / pthreads4w) for the Windows build.
#
# The bundled mosquitto (VendorMosquitto.cmake) is built WITH_THREADING=ON and,
# on Windows, does `find_package(PThreads4W REQUIRED)` and links
# PThreads4W::PThreads4W — mqtt_client.cpp relies on mosquitto_loop_start(),
# which spawns a background pthread. Upstream that dependency is satisfied by
# vcpkg's `pthreads` port; vendoring it here removes the *only* reason the
# Windows build needed vcpkg at all (OpenSSL/curl/zlib already come from the
# slicer's own deps superbuild).
#
# We compile the amalgamation unit pthread.c (which #includes the ~145
# implementation .c files) into a single static lib, using the VC flavour
# (C setjmp/longjmp cleanup) — the same one vcpkg ships as pthreadVC3.
function(obn_vendor_pthreads4w_setup)
    if(NOT WIN32)
        return()
    endif()
    if(TARGET PThreads4W::PThreads4W)
        return()
    endif()

    include(FetchContent)
    FetchContent_Declare(pthreads4w
        GIT_REPOSITORY https://github.com/jwinarske/pthreads4w.git
        GIT_TAG 904b10a2b5de3ac0a8b9dfe45bb36a2b157acd68
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
    )
    FetchContent_GetProperties(pthreads4w)
    if(NOT pthreads4w_POPULATED)
        FetchContent_Populate(pthreads4w)
    endif()

    # Arch selector mirrors pthreads4w's own CMakeLists.
    set(_p4w_arch __PTW32_ARCHX64)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(_p4w_arch __PTW32_ARCHX86)
    endif()

    add_library(obn_pthreads4w STATIC "${pthreads4w_SOURCE_DIR}/pthread.c")
    target_include_directories(obn_pthreads4w PUBLIC "${pthreads4w_SOURCE_DIR}")
    # PUBLIC defines are what <pthread.h> needs at *consumer* include time:
    #   __PTW32_STATIC_LIB -> drop __declspec(dllimport) from the public API
    #   __PTW32_CLEANUP_C  -> select the C (setjmp) cleanup flavour (== VC)
    target_compile_definitions(obn_pthreads4w
        PUBLIC  __PTW32_STATIC_LIB __PTW32_CLEANUP_C
        PRIVATE HAVE_CONFIG_H __PTW32_RC_MSC __PTW32_BUILD_INLINED ${_p4w_arch})
    if(MSVC)
        # Upstream third-party C; don't apply the plugin's warning flags to it.
        target_compile_options(obn_pthreads4w PRIVATE /w)
    endif()
    set_target_properties(obn_pthreads4w PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(obn_pthreads4w PUBLIC ws2_32 winmm)

    # The name mosquitto's find_package(PThreads4W) + target_link expect.
    add_library(PThreads4W::PThreads4W ALIAS obn_pthreads4w)
    message(STATUS "obn: using vendored pthreads4w (VC static, pinned 904b10a2)")
endfunction()
