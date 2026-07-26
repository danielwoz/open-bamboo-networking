add_executable(obn_fetch_device_cert main.cpp
    ../../src/auth.cpp
    ../../src/cert_store.cpp
    ../../src/cloud_auth.cpp
    ../../src/config.cpp
    ../../src/http_client.cpp
    ../../src/json_lite.cpp
    ../../src/lan_tls.cpp
    ../../src/log.cpp
    ../../src/os_compat.cpp
    ../../src/signing.cpp
)

target_include_directories(obn_fetch_device_cert PRIVATE
    ../../include
    ${OBN_GENERATED_DIR}
)

target_compile_definitions(obn_fetch_device_cert PRIVATE
    OBN_VERSION_STRING="${OBN_VERSION}"
    ABI_VERSION=${OBN_ABI_VERSION_HEX}
)

target_link_libraries(obn_fetch_device_cert PRIVATE
    obn_curl_iface
    OpenSSL::SSL
    OpenSSL::Crypto
)
