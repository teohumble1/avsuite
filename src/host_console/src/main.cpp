#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "avcore/config.hpp"
#include "avcore/severity.hpp"
#include "avengine/engine.hpp"
#include "avlogging/logger.hpp"

namespace {

std::filesystem::path ExecutableDirectory() {
    char buffer[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    return std::filesystem::path(buffer).parent_path();
}

void PrintUsage() {
    // Prefer "127.0.0.1" over "localhost" in the example below: cpp-httplib's
    // IPv6 (::1) resolution attempt for "localhost" hangs for ~2s against our
    // IPv4-only dev server before any fallback, observed in testing.
    std::cout << "AvSuite Phase 1 console host\n"
                 "Usage:\n"
                 "  avconsolehost.exe --scan <file-or-directory>\n"
                 "  avconsolehost.exe --regscan\n"
                 "  avconsolehost.exe --watch\n"
                 "  avconsolehost.exe --update <server-base-url, e.g. http://127.0.0.1:8443>\n"
                 "  avconsolehost.exe --quarantine-list\n"
                 "  avconsolehost.exe --quarantine-restore <id>\n"
                 "  avconsolehost.exe --quarantine-delete <id>\n"
                 "  avconsolehost.exe --history-clear\n"
                 "  avconsolehost.exe --export-lists <path.json>\n"
                 "  avconsolehost.exe --import-lists <path.json>\n";
}

void PrintDetection(const avcore::DetectionEvent& event) {
    AVLOG_WARN("[{}] {} :: {} -- {}", avcore::ToString(event.severity), event.rule_id, event.target_path,
               event.evidence);
}

std::atomic<bool> g_stop_requested{false};
std::condition_variable g_stop_cv;
std::mutex g_stop_mutex;

BOOL WINAPI ConsoleCtrlHandler(DWORD /*ctrl_type*/) {
    g_stop_requested = true;
    g_stop_cv.notify_all();
    return TRUE;
}

std::string ResolveNextToExe(const std::filesystem::path& exe_dir, const std::string& configured_path) {
    const std::filesystem::path path(configured_path);
    return path.is_absolute() ? configured_path : (exe_dir / path).string();
}

} // namespace

int main(int argc, char** argv) {
    const auto exe_dir = ExecutableDirectory();

    avcore::Config config = avcore::Config::LoadFromFile((exe_dir / "avsuite.json").string());
    config.database_path = ResolveNextToExe(exe_dir, config.database_path);
    config.log_path = ResolveNextToExe(exe_dir, config.log_path);
    config.yara_rules_directory = ResolveNextToExe(exe_dir, config.yara_rules_directory);
    config.quarantine_directory = ResolveNextToExe(exe_dir, config.quarantine_directory);

    avlogging::Logger::Init(config.log_path);

    const std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        PrintUsage();
        return 1;
    }

    avengine::Engine engine(config, PrintDetection);

    if (args[0] == "--scan" && args.size() >= 2) {
        const std::string& target = args[1];
        if (std::filesystem::is_directory(target)) {
            AVLOG_INFO("Scanning directory: {}", target);
            engine.ScanDirectory(target);
        } else {
            AVLOG_INFO("Scanning file: {}", target);
            engine.ScanFile(target);
        }
        AVLOG_INFO("Scan complete.");
        return 0;
    }

    if (args[0] == "--regscan") {
        AVLOG_INFO("Scanning autorun/persistence registry locations...");
        engine.ScanRegistry();
        AVLOG_INFO("Registry scan complete.");
        return 0;
    }

    if (args[0] == "--update" && args.size() >= 2) {
        AVLOG_INFO("Checking for signature DB updates from {}...", args[1]);
        const auto result = engine.CheckForSignatureUpdates(args[1]);
        if (!result.error.empty()) {
            AVLOG_WARN("Update check failed: {}", result.error);
            return 1;
        }
        if (result.updated) {
            AVLOG_INFO("Applied signature DB version {} ({} signatures updated).", result.version,
                       result.signature_count);
        } else {
            AVLOG_INFO("Already up to date (version {}).", result.version);
        }
        return 0;
    }

    if (args[0] == "--quarantine-list") {
        const auto records = engine.ListQuarantine();
        if (records.empty()) {
            std::cout << "Quarantine is empty.\n";
            return 0;
        }
        for (const auto& record : records) {
            std::cout << "[" << record.id << "] " << record.original_path << "  (" << record.rule_id << ", sha256 "
                       << record.sha256 << ")\n    -> " << record.quarantine_path << "\n";
        }
        return 0;
    }

    if (args[0] == "--quarantine-restore" && args.size() >= 2) {
        const std::int64_t id = std::stoll(args[1]);
        if (engine.RestoreFromQuarantine(id)) {
            AVLOG_INFO("Restored quarantine entry {} to its original location.", id);
            return 0;
        }
        AVLOG_WARN(
            "Could not restore quarantine entry {} (not found, already restored, or original path now occupied).",
            id);
        return 1;
    }

    if (args[0] == "--quarantine-delete" && args.size() >= 2) {
        const std::int64_t id = std::stoll(args[1]);
        if (engine.DeleteQuarantine(id)) {
            AVLOG_INFO("Permanently deleted quarantine entry {}.", id);
            return 0;
        }
        AVLOG_WARN("Could not delete quarantine entry {} (not found or already restored).", id);
        return 1;
    }

    if (args[0] == "--history-clear") {
        engine.ClearHistory();
        AVLOG_INFO("Detection history cleared.");
        return 0;
    }

    if (args[0] == "--export-lists" && args.size() >= 2) {
        const auto result = engine.ExportHashLists(args[1]);
        if (!result.success) {
            AVLOG_WARN("Export failed: {}", result.error);
            return 1;
        }
        AVLOG_INFO("Exported {} whitelist + {} blacklist hash(es) to {}.", result.whitelist_count,
                   result.blacklist_count, args[1]);
        return 0;
    }

    if (args[0] == "--import-lists" && args.size() >= 2) {
        const auto result = engine.ImportHashLists(args[1]);
        if (!result.success) {
            AVLOG_WARN("Import failed: {}", result.error);
            return 1;
        }
        AVLOG_INFO("Imported {} whitelist + {} blacklist hash(es) from {}.", result.whitelist_count,
                   result.blacklist_count, args[1]);
        return 0;
    }

    if (args[0] == "--watch") {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        AVLOG_INFO("Starting real-time protection (folder watch + ETW process feed). Press Ctrl+C to stop.");
        engine.StartRealtimeProtection();

        std::unique_lock<std::mutex> lock(g_stop_mutex);
        g_stop_cv.wait(lock, [] { return g_stop_requested.load(); });

        AVLOG_INFO("Stopping...");
        engine.Stop();
        return 0;
    }

    PrintUsage();
    return 1;
}
