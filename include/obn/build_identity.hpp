#pragma once

// Compile-time load banner text.
// OBN_VERSION_STRING — ABI version reported to the slicer (e.g. 02.07.00.99).
// OBN_RELEASE_BUILD / OBN_PROJECT_VERSION_STRING — release build identity.
// OBN_GIT_COMMIT / OBN_GIT_DIRTY — interim build identity when git is available.

#ifdef OBN_RELEASE_BUILD
#  define OBN_PLUGIN_LOAD_BANNER_MSG \
       "Loaded Open Bamboo Networking plugin, version " OBN_PROJECT_VERSION_STRING \
       ", ABI " OBN_VERSION_STRING
#else
#  ifdef OBN_GIT_COMMIT
#    ifdef OBN_GIT_DIRTY
#      define OBN_PLUGIN_LOAD_BANNER_MSG \
           "Loaded Open Bamboo Networking plugin, interim build, commit #" OBN_GIT_COMMIT \
           " (dirty), ABI " OBN_VERSION_STRING
#    else
#      define OBN_PLUGIN_LOAD_BANNER_MSG \
           "Loaded Open Bamboo Networking plugin, interim build, commit #" OBN_GIT_COMMIT \
           ", ABI " OBN_VERSION_STRING
#    endif
#  else
#    define OBN_PLUGIN_LOAD_BANNER_MSG \
         "Loaded Open Bamboo Networking plugin, interim build, ABI " OBN_VERSION_STRING
#  endif
#endif
