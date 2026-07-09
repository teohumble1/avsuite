#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace avcore {

// One file moved out of place by avremediation::Quarantine. Kept distinct
// from DetectionEvent (which can fire many times for the same file, e.g.
// once per matching YARA rule) -- a quarantine action happens once per file
// and needs its own restore/audit trail.
struct QuarantineRecord {
    std::int64_t id = 0;
    std::string original_path;
    std::string quarantine_path;
    std::string sha256;
    std::string rule_id;
    std::string evidence;
    std::chrono::system_clock::time_point quarantined_at = std::chrono::system_clock::now();
    bool restored = false;
};

} // namespace avcore
