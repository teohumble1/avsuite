#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "avcore/severity.hpp"

namespace avcore {

// One detection produced by any scan source (hash signature, YARA, PE heuristic,
// registry scan, or the behavioral rule engine). Persisted as-is into avstorage.
struct DetectionEvent {
    std::string rule_id;       // e.g. "SIG.HASH.0001", "YARA.PACKER.UPX", "BEH.LOLBIN_ARGS"
    std::string source;        // "hash_signature" | "yara" | "pe_analyzer" | "registry_scan" | "behavior_engine"
    Severity severity = Severity::Info;
    std::string target_path;   // file path or registry key path being reported on
    std::uint32_t process_id = 0;   // 0 if not process-related
    std::uint32_t parent_process_id = 0;
    std::string evidence;      // free-form human-readable detail
    std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now();
};

} // namespace avcore
