add_executable(liveview_capture
    main.cpp
    ${CMAKE_SOURCE_DIR}/src/auth.cpp
    ${CMAKE_SOURCE_DIR}/src/camera.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/AgoraUrl.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/CameraSourceFactory.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/JpegCameraSource.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/OssTutkCameraSource.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/oss_agora/OssAgoraBambuSource.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/oss_agora/OssAgoraEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/oss_agora/OssAgoraSignaling.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/oss_tutk/IotcClient.cpp
    ${CMAKE_SOURCE_DIR}/src/cloud_auth.cpp
    ${CMAKE_SOURCE_DIR}/src/config.cpp
    ${CMAKE_SOURCE_DIR}/src/http_client.cpp
    ${CMAKE_SOURCE_DIR}/src/json_lite.cpp
    ${CMAKE_SOURCE_DIR}/src/lan_tls.cpp
    ${CMAKE_SOURCE_DIR}/src/log.cpp
    ${CMAKE_SOURCE_DIR}/src/net_compat.cpp
    ${CMAKE_SOURCE_DIR}/src/os_compat.cpp
    ${CMAKE_SOURCE_DIR}/src/signing.cpp
)
target_include_directories(liveview_capture PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OBN_GENERATED_DIR}
)
target_compile_definitions(liveview_capture PRIVATE
    OBN_VERSION_STRING="${OBN_VERSION}"
    ABI_VERSION=${OBN_ABI_VERSION_HEX}
)
target_link_libraries(liveview_capture PRIVATE
    obn_curl_iface
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_features(liveview_capture PRIVATE cxx_std_17)
