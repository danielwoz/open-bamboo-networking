# OpenSSL 3.5+ (e.g. Fedora 44 openssl-devel) no longer ships openssl/engine.h when
# ENGINE is disabled. Mosquitto v2.1.2 includes it unconditionally; wrap with
# OPENSSL_NO_ENGINE like upstream OpenSSL headers. See:
# https://github.com/ClusterM/open-bambu-networking/issues/19

function(obn_patch_mosquitto_openssl35_engine _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto patch: missing lib/ under '${_src_root}'")
    endif()

    set(_mark "obn: OpenSSL 3.5+ engine.h guard (issue #19)")
    set(_h "${_src_root}/lib/tls_mosq.h")
    file(READ "${_h}" _tls)
    if(NOT _tls MATCHES "${_mark}")
        string(REPLACE
            "#include <openssl/engine.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#include <openssl/engine.h>\n#endif"
            _tls "${_tls}")
        file(WRITE "${_h}" "${_tls}")
    endif()

    set(_c "${_src_root}/lib/net_mosq.c")
    file(READ "${_c}" _net)
    if(NOT _net MATCHES "${_mark}")
        string(REPLACE
            "#include <openssl/engine.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#include <openssl/engine.h>\n#endif"
            _net "${_net}")
        file(WRITE "${_c}" "${_net}")
    endif()

    set(_o "${_src_root}/lib/options.c")
    file(READ "${_o}" _opt)
    if(NOT _opt MATCHES "${_mark}")
        string(REPLACE
            "#include <openssl/engine.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#include <openssl/engine.h>\n#endif"
            _opt "${_opt}")
        file(WRITE "${_o}" "${_opt}")
    endif()
endfunction()
