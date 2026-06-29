// SPDX-License-Identifier: AGPL-3.0-only
// Orca Slicer plate normalisation — filename rename + in-ZIP rewrite.
//
// Orca's bbs_3mf exporter writes plate_0.* entries (plate_0.gcode,
// plate_no_light_0.png, top_0.png, pick_0.png) and similarly names the
// local file *_plate_0.gcode.3mf. H2D/H2S firmware expects plate_1.*
// in both the archive entries and the project_file MQTT payload.
//
// Two entry points are exported into the obn::print_job namespace:
//
//   to_print_basename(fname)
//       Strip path prefix, normalise plate_0→plate_1 in the name,
//       ensure the .gcode.3mf extension. Used when computing the
//       remote STOR filename and the project_file url= field.
//
//   normalise_orca_plate_to_one(threemf_path)
//       Rewrites the 3MF ZIP in-place: renames Metadata/plate_0.*
//       entries to Metadata/plate_1.*, patches model_settings.config,
//       and bumps plater_id from "0" to "1". No-op when the archive
//       already has plate_1.gcode or lacks plate_0.gcode.
//
// ZIP I/O uses miniz (public-domain, vendored at third_party/miniz/).
// The normalise step must run BEFORE the FTPS STOR so the printer sees
// a correct archive and the MD5 computed afterward matches what landed.

#include "obn/print_job.hpp"
#include "obn/log.hpp"

// miniz is a C library — wrap in extern "C" to avoid link-name mangling.
extern "C" {
#include "miniz/miniz.h"
}

#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

namespace obn::print_job {

// ---------------------------------------------------------------------------
// to_print_basename
// ---------------------------------------------------------------------------

std::string to_print_basename(std::string fname)
{
    // 1. Strip directory prefix.
    {
        auto slash = fname.find_last_of("/\\");
        if (slash != std::string::npos)
            fname = fname.substr(slash + 1);
    }

    if (fname.empty()) return "print.gcode.3mf";

    // 2. Normalise plate_0 → plate_1 in the name (first occurrence only;
    //    filenames don't legitimately contain more than one plate index).
    {
        const std::string needle = "plate_0";
        auto pos = fname.find(needle);
        if (pos != std::string::npos)
            fname.replace(pos, needle.size(), "plate_1");
    }

    // 3. Ensure .gcode.3mf extension.
    auto ends_with_ci = [](const std::string& s, const char* suf) {
        std::size_t n = std::strlen(suf);
        if (s.size() < n) return false;
        for (std::size_t i = 0; i < n; ++i) {
            char a = s[s.size() - n + i];
            char b = suf[i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (a != b) return false;
        }
        return true;
    };

    if (ends_with_ci(fname, ".gcode.3mf")) return fname;

    // Strip bare ".3mf" and re-add ".gcode.3mf".
    if (ends_with_ci(fname, ".3mf"))
        fname.erase(fname.size() - 4);

    return fname + ".gcode.3mf";
}

// ---------------------------------------------------------------------------
// normalise_orca_plate_to_one helpers
// ---------------------------------------------------------------------------

namespace {

bool zip_has_entry(mz_zip_archive& z, const std::string& target)
{
    const mz_uint n = mz_zip_reader_get_num_files(&z);
    char name[512];
    for (mz_uint i = 0; i < n; ++i) {
        if (mz_zip_reader_get_filename(&z, i, name, sizeof(name)) == 0) continue;
        if (target == name) return true;
    }
    return false;
}

std::string str_replace_all(std::string s, const std::string& from, const std::string& to)
{
    if (from.empty()) return s;
    for (std::size_t p = 0; (p = s.find(from, p)) != std::string::npos; p += to.size())
        s.replace(p, from.size(), to);
    return s;
}

// Remap a ZIP entry name: plate_0.* → plate_1.*,
// plate_no_light_0.* → plate_no_light_1.*, etc.
// Order matters: longest prefix first.
std::string remap_plate_entry(const std::string& nm)
{
    if (nm.rfind("Metadata/plate_no_light_0", 0) == 0)
        return "Metadata/plate_no_light_1" + nm.substr(25);
    if (nm.rfind("Metadata/plate_0", 0) == 0)
        return "Metadata/plate_1" + nm.substr(16);
    if (nm.rfind("Metadata/top_0", 0) == 0)
        return "Metadata/top_1" + nm.substr(14);
    if (nm.rfind("Metadata/pick_0", 0) == 0)
        return "Metadata/pick_1" + nm.substr(15);
    return nm;
}

} // namespace

// ---------------------------------------------------------------------------
// normalise_orca_plate_to_one
// ---------------------------------------------------------------------------

bool normalise_orca_plate_to_one(const std::string& in_path)
{
    mz_zip_archive in{};
    if (!mz_zip_reader_init_file(&in, in_path.c_str(), 0)) {
        OBN_ERROR("plate_norm: open failed: %s", in_path.c_str());
        return false;
    }

    // Orca shape: plate_0.gcode present AND plate_1.gcode absent.
    // Both conditions must hold — if neither matches it's a BBS-style spool
    // or a non-print archive; skip silently.
    const bool has_plate_0 = zip_has_entry(in, "Metadata/plate_0.gcode");
    const bool has_plate_1 = zip_has_entry(in, "Metadata/plate_1.gcode");
    if (!has_plate_0 || has_plate_1) {
        mz_zip_reader_end(&in);
        OBN_DEBUG("plate_norm: no-op (has_plate_0=%d has_plate_1=%d) %s",
                  (int)has_plate_0, (int)has_plate_1, in_path.c_str());
        return true;
    }

    const std::string out_path = in_path + ".normalised";
    std::error_code ec;
    std::filesystem::remove(out_path, ec);

    mz_zip_archive out{};
    if (!mz_zip_writer_init_file(&out, out_path.c_str(), 0)) {
        OBN_ERROR("plate_norm: create temp failed: %s", out_path.c_str());
        mz_zip_reader_end(&in);
        return false;
    }

    bool ok = true;
    int  n_renamed = 0;
    const mz_uint n_in = mz_zip_reader_get_num_files(&in);

    for (mz_uint i = 0; i < n_in && ok; ++i) {
        char name[512];
        if (mz_zip_reader_get_filename(&in, i, name, sizeof(name)) == 0) continue;
        const std::string in_name(name);
        const std::string out_name = remap_plate_entry(in_name);

        if (in_name == "Metadata/model_settings.config") {
            // Patch all plate_0 path references and bump plater_id 0→1.
            std::size_t sz = 0;
            void* data = mz_zip_reader_extract_to_heap(&in, i, &sz, 0);
            if (!data) { ok = false; break; }
            std::string body(static_cast<const char*>(data), sz);
            mz_free(data);
            body = str_replace_all(body, "Metadata/plate_no_light_0",
                                         "Metadata/plate_no_light_1");
            body = str_replace_all(body, "Metadata/plate_0",
                                         "Metadata/plate_1");
            body = str_replace_all(body, "Metadata/top_0",
                                         "Metadata/top_1");
            body = str_replace_all(body, "Metadata/pick_0",
                                         "Metadata/pick_1");
            // plater_id is plate_index + 1 upstream; Orca ships it as "0".
            body = str_replace_all(body,
                "key=\"plater_id\" value=\"0\"",
                "key=\"plater_id\" value=\"1\"");
            if (!mz_zip_writer_add_mem(&out, in_name.c_str(),
                                       body.data(), body.size(),
                                       MZ_DEFAULT_COMPRESSION)) {
                ok = false; break;
            }
        } else if (out_name != in_name) {
            std::size_t sz = 0;
            void* data = mz_zip_reader_extract_to_heap(&in, i, &sz, 0);
            if (!data) { ok = false; break; }
            bool added = mz_zip_writer_add_mem(&out, out_name.c_str(),
                                               data, sz,
                                               MZ_DEFAULT_COMPRESSION);
            mz_free(data);
            if (!added) { ok = false; break; }
            ++n_renamed;
        } else {
            // Unchanged: bulk-copy preserving compression.
            if (!mz_zip_writer_add_from_zip_reader(&out, &in, i)) {
                ok = false; break;
            }
        }
    }

    if (ok && !mz_zip_writer_finalize_archive(&out)) ok = false;
    if (!mz_zip_writer_end(&out))                    ok = false;
    mz_zip_reader_end(&in);

    if (!ok) {
        std::filesystem::remove(out_path, ec);
        OBN_ERROR("plate_norm: rewrite failed: %s", in_path.c_str());
        return false;
    }

    std::filesystem::rename(out_path, in_path, ec);
    if (ec) {
        OBN_ERROR("plate_norm: rename failed (%s): %s",
                  ec.message().c_str(), in_path.c_str());
        std::filesystem::remove(out_path, ec);
        return false;
    }

    OBN_INFO("plate_norm: rewrote %s (entries renamed=%d)", in_path.c_str(), n_renamed);
    return true;
}

} // namespace obn::print_job
