# Standalone probe for the BambuSource C ABI. Dials a printer's :6000 video
# tunnel outside DirectShow/GStreamer so "the slicer shows Playing but the pane
# is black" can be resolved into "frames arrive" vs "the transport is dead".
#
#   bs_probe "bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>&device=<sn>"
#
# Exit code 0 when frames were read, 3 when the tunnel opened but produced none.
add_executable(bs_probe main.cpp)
target_compile_features(bs_probe PRIVATE cxx_std_17)
