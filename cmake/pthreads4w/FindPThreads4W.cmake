# FindPThreads4W.cmake — shim for the vendored pthreads4w.
#
# VendorPThreads4W.cmake (invoked from VendorMosquitto.cmake BEFORE the bundled
# mosquitto's add_subdirectory) FetchContent's pthreads4w, builds it, and
# creates the PThreads4W::PThreads4W target, then prepends this directory to
# CMAKE_MODULE_PATH. So by the time mosquitto runs `find_package(PThreads4W
# REQUIRED)`, the target already exists and all we must do is report the
# package as found — no on-disk config/lib to locate.
if(TARGET PThreads4W::PThreads4W)
    set(PThreads4W_FOUND TRUE)
    set(PThreads4W_LIBRARIES PThreads4W::PThreads4W)
else()
    set(PThreads4W_FOUND FALSE)
    if(PThreads4W_FIND_REQUIRED)
        message(FATAL_ERROR
            "FindPThreads4W shim: PThreads4W::PThreads4W target does not exist. "
            "obn_vendor_pthreads4w_setup() must run before this find_package.")
    endif()
endif()
