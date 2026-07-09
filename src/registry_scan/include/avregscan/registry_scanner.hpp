#pragma once

#include <string>
#include <vector>

#include "avcore/detection_event.hpp"

namespace avregscan {

struct AutorunEntry {
    std::string location;       // e.g. "HKLM\\...\\Run" or "IFEO\\notepad.exe"
    std::string value_name;     // e.g. "OneDrive" or "Debugger"
    std::string raw_value;      // raw registry value data
    std::string resolved_executable_path;
};

// Read-only enumeration of known autorun/persistence registry locations
// (Run, RunOnce, Winlogon Shell/Userinit, AppInit_DLLs, Image File Execution
// Options debugger hijacks, and service ImagePaths).
std::vector<AutorunEntry> ScanAutorunLocations();

// Pure heuristic over already-collected entries -- no registry I/O, so this
// is unit-testable with synthetic entries.
std::vector<avcore::DetectionEvent> EvaluateAutorunEntries(const std::vector<AutorunEntry>& entries);

// ScanAutorunLocations() + EvaluateAutorunEntries() in one call.
std::vector<avcore::DetectionEvent> ScanAndEvaluate();

// Best-effort extraction of the leading executable path from a registry
// command value: handles a quoted path, or a bare/unquoted path (walking
// forward to the first token ending in .exe/.dll/.sys when the path itself
// contains spaces).
std::string ExtractExecutablePath(const std::string& value);

} // namespace avregscan
