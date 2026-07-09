#pragma once

#include <string>
#include <vector>

namespace avcore {

struct ScheduledScanConfig {
    bool enabled = false;
    std::string interval = "daily"; // "daily", "weekly", "on_boot"
    std::string time_hhmm = "02:00";
    std::string target_path; // empty = scan watch_directories
};

// Phase 1 runtime configuration. Loaded from a JSON file by host_console;
// defaults here are safe/sane if no config file is present.
struct Config {
    std::vector<std::string> watch_directories = {
        "%LOCALAPPDATA%\\Temp",
        "%APPDATA%",
        "%USERPROFILE%\\Downloads",
    };
    std::string database_path = "avsuite.db";
    std::string log_path = "avsuite.log";
    std::string yara_rules_directory = "yara_rules";
    std::string quarantine_directory = "quarantine";
    int debounce_ms = 750;
    ScheduledScanConfig scheduled_scan;

    // Path to a GGUF model file for the built-in AI assistant (e.g. Qwen2.5-3B
    // or Phi-3.5-mini). Leave empty to disable the AI page. The file is NOT
    // bundled with the app -- download from HuggingFace separately.
    std::string ai_model_path;

    // Optional VirusTotal API v3 key. When non-empty, the dashboard history
    // page exposes a "VT Lookup" button that queries the VT Files endpoint
    // for a selected detection's SHA-256. Get a free key at virustotal.com.
    std::string virustotal_api_key;

    // Optional abuse.ch MalwareBazaar Auth-Key. When non-empty, the Threat
    // Intel dashboard page can pull the recent-malware-hash CSV feed and
    // merge new hashes into the local blacklist. Get a free key at
    // bazaar.abuse.ch (Account -> API Key). Left empty, the fetch is
    // attempted anonymously and will show abuse.ch's error if a key is required.
    std::string malwarebazaar_api_key;

    // Base URL of an avupdateserver instance (see src/update_server) used by
    // the dashboard's Self-Update page to check for and download new signed
    // app builds. Defaults to a local dev instance; point it at a real host
    // if one is deployed. Empty disables the update check.
    std::string update_server_url = "http://localhost:8443";

    // Absolute path of the JSON file this config was loaded from;
    // empty if constructed from defaults (no file present).
    std::string config_file_path;

    static Config LoadFromFile(const std::string& path);
    bool SaveToFile(const std::string& path) const;
};

} // namespace avcore
