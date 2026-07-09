#include "avregscan/registry_scanner.hpp"

#include "avcore/path_utils.hpp"
#include "avpe/authenticode.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <optional>

namespace avregscan {

namespace {

std::optional<std::string> ReadStringValue(HKEY key, const std::string& value_name) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExA(key, value_name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0) return std::nullopt;

    std::string buffer(size, '\0');
    if (RegQueryValueExA(key, value_name.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &size) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }
    while (!buffer.empty() && buffer.back() == '\0') buffer.pop_back();
    return buffer;
}

void ScanValueListKey(HKEY hive, const std::string& subkey, const std::string& location_label,
                       std::vector<AutorunEntry>& out) {
    HKEY key;
    if (RegOpenKeyExA(hive, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return;

    DWORD index = 0;
    char name_buf[256];
    while (true) {
        DWORD name_len = sizeof(name_buf);
        DWORD type = 0;
        const LONG rc = RegEnumValueA(key, index, name_buf, &name_len, nullptr, &type, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS) break;
        ++index;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        if (auto value = ReadStringValue(key, name_buf)) {
            AutorunEntry entry;
            entry.location = location_label;
            entry.value_name = name_buf;
            entry.raw_value = *value;
            entry.resolved_executable_path = ExtractExecutablePath(*value);
            out.push_back(std::move(entry));
        }
    }
    RegCloseKey(key);
}

void ScanSingleValue(HKEY hive, const std::string& subkey, const std::string& value_name,
                      const std::string& location_label, std::vector<AutorunEntry>& out) {
    HKEY key;
    if (RegOpenKeyExA(hive, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return;
    if (auto value = ReadStringValue(key, value_name)) {
        AutorunEntry entry;
        entry.location = location_label;
        entry.value_name = value_name;
        entry.raw_value = *value;
        entry.resolved_executable_path = ExtractExecutablePath(*value);
        out.push_back(std::move(entry));
    }
    RegCloseKey(key);
}

// Shared by IFEO and Services scans: enumerate subkeys of `base`, and for
// each one that has `target_value_name` set, record an AutorunEntry.
void ScanSubkeysForValue(const std::string& base, const std::string& target_value_name,
                          const std::string& location_prefix, std::vector<AutorunEntry>& out) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return;

    DWORD index = 0;
    char subkey_name[256];
    while (true) {
        DWORD name_len = sizeof(subkey_name);
        const LONG rc = RegEnumKeyExA(key, index, subkey_name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS) break;
        ++index;

        const std::string full_path = base + "\\" + subkey_name;
        HKEY subkey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_path.c_str(), 0, KEY_READ, &subkey) == ERROR_SUCCESS) {
            if (auto value = ReadStringValue(subkey, target_value_name)) {
                AutorunEntry entry;
                entry.location = location_prefix + subkey_name;
                entry.value_name = target_value_name;
                entry.raw_value = *value;
                entry.resolved_executable_path = ExtractExecutablePath(*value);
                out.push_back(std::move(entry));
            }
            RegCloseKey(subkey);
        }
    }
    RegCloseKey(key);
}

} // namespace

std::string ExtractExecutablePath(const std::string& value) {
    const size_t start = value.find_first_not_of(" \t");
    if (start == std::string::npos) return std::string();
    const std::string trimmed = value.substr(start);

    if (trimmed.front() == '"') {
        const size_t close = trimmed.find('"', 1);
        return close != std::string::npos ? trimmed.substr(1, close - 1) : trimmed.substr(1);
    }

    const size_t first_space = trimmed.find(' ');
    if (first_space == std::string::npos) return trimmed;

    static const std::array<const char*, 3> kExeExtensions = {".exe", ".dll", ".sys"};
    size_t search_pos = 0;
    while (true) {
        const size_t next_space = trimmed.find(' ', search_pos);
        const std::string candidate = trimmed.substr(0, next_space == std::string::npos ? trimmed.size() : next_space);
        const std::string lower = avcore::ToLowerAscii(candidate);
        for (const char* ext : kExeExtensions) {
            const size_t ext_len = std::strlen(ext);
            if (lower.size() >= ext_len && lower.compare(lower.size() - ext_len, ext_len, ext) == 0) {
                return candidate;
            }
        }
        if (next_space == std::string::npos) break;
        search_pos = next_space + 1;
    }
    return trimmed.substr(0, first_space);
}

std::vector<AutorunEntry> ScanAutorunLocations() {
    std::vector<AutorunEntry> entries;

    ScanValueListKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\...\\Run", entries);
    ScanValueListKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM\\...\\RunOnce",
                      entries);
    ScanValueListKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                      "HKLM\\WOW6432Node\\...\\Run", entries);
    ScanValueListKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                      "HKLM\\WOW6432Node\\...\\RunOnce", entries);
    ScanValueListKey(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\...\\Run", entries);
    ScanValueListKey(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\...\\RunOnce",
                      entries);

    ScanSingleValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell",
                     "HKLM\\...\\Winlogon", entries);
    ScanSingleValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit",
                     "HKLM\\...\\Winlogon", entries);
    // Note: AppInit_DLLs can hold multiple space-separated DLL paths; this v1
    // heuristic only resolves the first one via ExtractExecutablePath.
    ScanSingleValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs",
                     "HKLM\\...\\Windows", entries);

    ScanSubkeysForValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "Debugger",
                         "HKLM\\...\\Image File Execution Options\\", entries);
    ScanSubkeysForValue("SYSTEM\\CurrentControlSet\\Services", "ImagePath",
                         "HKLM\\SYSTEM\\CurrentControlSet\\Services\\", entries);

    return entries;
}

std::vector<avcore::DetectionEvent> EvaluateAutorunEntries(const std::vector<AutorunEntry>& entries) {
    std::vector<avcore::DetectionEvent> detections;

    for (const auto& entry : entries) {
        if (entry.resolved_executable_path.empty()) continue;
        if (!std::filesystem::exists(entry.resolved_executable_path)) continue; // orphaned, not actionable

        // Signature is checked first and is the deciding factor: plenty of
        // legitimate consumer apps (Discord, Steam games, browser updaters,
        // ...) install signed per-user updater/launcher binaries under
        // AppData and register them in Run -- flagging on location alone
        // would make this rule fire on most ordinary machines. Location only
        // enriches the evidence message once a binary is already unsigned.
        if (avpe::IsAuthenticodeSigned(entry.resolved_executable_path)) continue;

        const std::string reason = avcore::IsUnderUserWritableDir(entry.resolved_executable_path)
                                        ? "target points to a user-writable drop location and has no valid "
                                          "Authenticode signature"
                                        : "target binary has no valid Authenticode signature";

        avcore::DetectionEvent detection;
        detection.rule_id = "REG.SUSPICIOUS_AUTORUN";
        detection.source = "registry_scan";
        detection.severity = avcore::Severity::Suspicious;
        detection.target_path = entry.location + " :: " + entry.value_name;
        detection.evidence = "Autorun entry '" + entry.value_name + "' at " + entry.location + " -> '" +
                              entry.raw_value + "' (" + reason + ").";
        detections.push_back(std::move(detection));
    }
    return detections;
}

std::vector<avcore::DetectionEvent> ScanAndEvaluate() {
    return EvaluateAutorunEntries(ScanAutorunLocations());
}

} // namespace avregscan
