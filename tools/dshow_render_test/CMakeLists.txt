# Builds a DirectShow graph from BambuSource exactly as wxMediaCtrl does
# (Intelligent Connect through the system MJPEG Decompressor) and grabs the
# RENDERED RGB via a SampleGrabber, saving the first frame to rendered.bmp.
# Resolves "the slicer shows Playing but the pane is black" into "the decode
# path builds and produces a real image" vs "it does not". Windows-only.
#
#   dshow_render_test "bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>&device=<sn>"
#
# Loads the registered BambuSource.dll (HKCU CLSID). Exit 0 = frames rendered.
add_executable(dshow_render_test main.cpp)
target_link_libraries(dshow_render_test PRIVATE strmiids ole32 oleaut32)
target_compile_features(dshow_render_test PRIVATE cxx_std_17)
