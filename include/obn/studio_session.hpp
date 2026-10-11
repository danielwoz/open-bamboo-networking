#pragma once

// Import a cloud user session from Bambu Studio's own stored credentials, so a
// user already logged in through Bambu Studio does not have to log in again
// through the slicer this plugin is loaded by.
//
// Bambu Studio keeps the session in <config>/BambuNetworkEngine.conf, encrypted
// with AES-128-ECB under the 16-byte key in <config>/network_engine.key. The
// key is the same for every install (it identifies the network engine to Bambu,
// it is not per-user), so a build may also carry it embedded (see
// cmake/obn_embedded_signing.h.in) for when the key file is not present.

#include "obn/auth.hpp"

#include <optional>
#include <string>

namespace obn::studio_session {

// Returns a logged-in Session parsed from Bambu Studio's BambuNetworkEngine.conf
// when it can be found and decrypted. Searches `config_dir` first, then the
// platform's default Bambu Studio config directory, for both the conf and the
// network_engine.key; falls back to the build-time-embedded key when no key
// file is found. Returns std::nullopt when the conf is absent, no key is
// available, or decryption/parsing yields no usable token.
std::optional<obn::auth::Session> import_from_studio_conf(const std::string& config_dir);

} // namespace obn::studio_session
