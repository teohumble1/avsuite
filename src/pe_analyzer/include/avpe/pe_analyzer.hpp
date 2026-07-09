#pragma once

#include <optional>
#include <string>
#include <vector>

#include "avcore/detection_event.hpp"

namespace avpe {

struct PeAnalysisResult {
    bool is_signed = false;
    double max_section_entropy = 0.0;
    std::vector<std::string> packer_section_hits;
    bool has_injection_import_combo = false;   // VirtualAlloc+WriteProcessMemory+CreateRemoteThread
    bool has_nt_injection_combo = false;       // NtCreateThreadEx/RtlCreateUserThread + alloc
    bool has_minimal_import_loader = false;    // VirtualProtect+CreateThread but no process/service APIs = dynamic API resolver
    bool has_hollowing_combo = false;          // NtUnmapViewOfSection+WriteProcessMemory+SetThreadContext+ResumeThread+CreateProcess
    int suspicious_import_count = 0;           // count of high-risk API names in import table
    int total_import_count = 0;                // total imported functions (low = possibly packed)
    std::vector<std::string> imported_dlls;
};

// Returns nullopt if `path` cannot be read or isn't a valid PE image.
std::optional<PeAnalysisResult> AnalyzeFile(const std::string& path);

// Converts an analysis result into zero or more DetectionEvents.
std::vector<avcore::DetectionEvent> ToDetectionEvents(const std::string& path, const PeAnalysisResult& result);

} // namespace avpe
