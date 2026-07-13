#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "avbehavior/process_event.hpp"
#include "avcore/config.hpp"
#include "avcore/detection_event.hpp"
#include "avcore/quarantine_record.hpp"
#include "avstorage/database.hpp"

namespace avengine {

// Forward-declarations of kernel callback monitors (BƯỚC 1: Kernel Callbacks)
class ProcessMonitor;
class DllMonitor;
class HandleMonitor;
class RegistryMonitor;

using DetectionCallback = std::function<void(const avcore::DetectionEvent&)>;
using ProgressCallback = std::function<void(int current, int total)>;
using EtwRawCallback = std::function<void(const avbehavior::ProcessEvent&)>;

struct UpdateResult {
    bool updated = false;        // true only if a newer signature DB was downloaded and applied
    std::string version;         // version now applied locally (unchanged if already up to date)
    int signature_count = 0;     // signatures upserted this call (0 if already up to date)
    std::string error;           // empty on success; set if the server was unreachable or the payload was rejected
};

struct HashListTransferResult {
    bool success = false;
    std::string error;          // empty on success
    int whitelist_count = 0;    // entries written (export) or upserted (import)
    int blacklist_count = 0;
};

struct ThreatIntelEntry {
    std::string sha256;
    std::string signature;   // malware family/signature name, e.g. "TrickBot"
    std::string first_seen;  // UTC timestamp as reported by the feed
};

struct ThreatIntelFetchResult {
    bool success = false;
    std::string error;   // empty on success
    std::vector<ThreatIntelEntry> entries;
};

// Orchestrates every Phase 1 detection source behind one entry point:
//   - on-demand file/directory scan (hash signature + YARA + PE analyzer)
//   - on-demand registry autorun scan
//   - real-time folder watch (same file-scan pipeline, triggered by avrealtime)
//   - live ETW process-behavior feed (avbehavior::RuleEngine via avetw)
// Every detection, regardless of source, is persisted to avstorage and
// forwarded to the caller's DetectionCallback.
class Engine {
public:
    Engine(avcore::Config config, DetectionCallback on_detection);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    void ScanFile(const std::string& path);
    void ScanDirectory(const std::string& directory, ProgressCallback on_progress = {});
    void ScanRegistry();

    // Cancels any in-progress ScanDirectory or ScanPersistence call. Safe to
    // call from any thread; the scan will stop after the current file finishes.
    void CancelScan();

    // Scans three persistence vectors for suspicious entries:
    //   - Scheduled Tasks   (C:\Windows\System32\Tasks\*, XML <Command> paths)
    //   - Services          (Win32 services whose binary lives outside Windows/ProgramFiles)
    //   - WMI subscriptions (ROOT\subscription __EventConsumer / __EventFilter)
    // Findings are emitted as PERSIST.* detection events and any identified
    // binaries are passed through the normal file-scan pipeline.
    void ScanPersistence(ProgressCallback on_progress = {});

    // Scans the virtual address space of a running process with YARA.
    // Enumerates all committed, readable private/mapped regions via
    // VirtualQueryEx and runs ScanBytes on each. Regions >64 MB are skipped
    // to bound memory usage. Returns number of detections emitted.
    int ScanProcessMemory(std::uint32_t pid);

    // Calls ScanProcessMemory on every process visible to EnumProcesses.
    // Runs synchronously -- callers should dispatch to a background thread.
    // Returns total detections across all processes.
    int ScanAllProcesses(ProgressCallback on_progress = {});

    // Registers a callback that is invoked for every raw ETW process-creation
    // event (before behavior-rule evaluation). Safe to call before or after
    // StartRealtimeProtection -- guarded by an internal mutex.
    void SetEtwRawCallback(EtwRawCallback cb);

    // Reads back persisted detections (most recent first) -- used by the
    // dashboard to populate scan history on startup.
    std::vector<avcore::DetectionEvent> RecentDetections(int limit = 200);

    // Any Malicious-severity detection from ScanFile/ScanDirectory or the
    // folder watcher is moved to config.quarantine_directory automatically
    // (see avremediation::Quarantine) -- these two calls are how a caller
    // reviews or undoes that. Not wired into the minifilter's real-time
    // block path: a denied file-create may not have produced a file on disk
    // yet, so there is nothing safe to move at that point.
    std::vector<avcore::QuarantineRecord> ListQuarantine();
    bool RestoreFromQuarantine(std::int64_t quarantine_id);

    // Backs the dashboard's home/status page.
    avstorage::DbStats GetStats();

    // Permanently deletes a quarantined file (not the original -- that's
    // already gone, moved away by the quarantine action). Irreversible;
    // callers should confirm with the user first.
    bool DeleteQuarantine(std::int64_t quarantine_id);

    // Clears every persisted detection (and the scan records they belong
    // to). Does not touch quarantined files -- those are tracked/removed
    // separately via *Quarantine().
    void ClearHistory();

    // Hash blacklist/whitelist only (not path-based whitelist entries,
    // which aren't portable across machines). Export overwrites `path`;
    // import upserts into the local DB without clearing existing entries.
    HashListTransferResult ExportHashLists(const std::string& path);
    HashListTransferResult ImportHashLists(const std::string& path);

    void AddToWhitelist(const std::string& sha256, const std::string& note);
    void RemoveFromWhitelist(const std::string& sha256);
    void AddToBlacklist(const std::string& sha256, const std::string& note);
    void RemoveFromBlacklist(const std::string& sha256);
    std::vector<avstorage::HashListEntry> ListWhitelistHashes();
    std::vector<avstorage::HashListEntry> ListBlacklistHashes();

    // Fetches <server_base_url>/manifest.json; if it reports a version newer
    // than what's locally applied, downloads /signatures.json, verifies its
    // SHA-256 against the manifest before touching the local DB, then
    // upserts every entry. See src/update_server for the matching dev-stub
    // server (plain HTTP, no auth -- not yet suitable for real deployment).
    UpdateResult CheckForSignatureUpdates(const std::string& server_base_url);

    // Queries the VirusTotal API v3 for a SHA-256 hash and returns a human-
    // readable summary (detection ratio, threat names, etc.). Requires that
    // config.virustotal_api_key is non-empty; returns an error string otherwise.
    // Blocks for the duration of the HTTP round-trip -- callers should
    // dispatch to a background thread.
    std::string LookupVirusTotal(const std::string& sha256);

    // Same idea as LookupVirusTotal but for an IP address (VT /ip_addresses
    // endpoint: reputation, AS owner, country, detection stats) and a domain
    // (VT /domains endpoint: reputation, categories, detection stats). Used
    // by the OSINT Hub page's IOC-lookup tool. Same requirements/behavior
    // (needs virustotal_api_key, blocks -- call from a background thread).
    std::string LookupVirusTotalIp(const std::string& ip);
    std::string LookupVirusTotalDomain(const std::string& domain);

    // Fetches abuse.ch MalwareBazaar's "recent additions" CSV feed (public
    // threat-intel: SHA-256 hashes of malware samples seen in the wild in
    // the last ~48h, with a signature/family name). Uses
    // config.malwarebazaar_api_key as the Auth-Key header if set (get a free
    // key at bazaar.abuse.ch); attempted anonymously otherwise, which
    // abuse.ch may reject. Does NOT touch the local blacklist itself --
    // callers merge entries in via AddToBlacklist so the dashboard can skip
    // hashes already present and show what's new. Blocks for the duration
    // of the HTTP round-trip -- callers should dispatch to a background thread.
    ThreatIntelFetchResult FetchMalwareBazaarRecent();

    // Starts the folder watcher, live ETW behavior feed, and (if
    // AvMiniFilter.sys is loaded) the real-time *blocking* minifilter
    // client, all on background threads. Returns immediately. Both the ETW
    // feed (requires elevation) and the minifilter client (requires the
    // Phase 4 kernel driver) degrade gracefully: if either fails to start,
    // a SYS.ETW_START_FAILED or SYS.MINIFILTER_CONNECT_FAILED status event
    // is delivered through the same DetectionCallback rather than throwing,
    // so folder-watch detection still runs even when one or both can't.
    void StartRealtimeProtection();
    void Stop();

    // Updates the scheduled-scan config and restarts the background schedule
    // thread if realtime protection is running. Safe to call from any thread.
    void SetScheduledScan(const avcore::ScheduledScanConfig& config);

    // Performance metrics: returns JSON with scan timing data (last 1000 scans).
    // Each entry includes: file_path, file_size_bytes, hash_check_ms, yara_scan_ms,
    // pe_analysis_ms, total_scan_ms, detections_count. Useful for identifying
    // performance bottlenecks and false-positive patterns.
    std::string ExportPerformanceMetrics();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace avengine
