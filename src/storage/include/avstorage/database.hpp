#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "avcore/detection_event.hpp"
#include "avcore/quarantine_record.hpp"

struct sqlite3;

namespace avstorage {

struct SignatureRecord {
    std::string sha256;
    std::string malware_name;
    avcore::Severity severity;
};

struct HashListEntry {
    std::string sha256;
    std::string note;
};

struct DbStats {
    std::int64_t total_scans = 0;
    std::int64_t total_detections = 0;
    std::int64_t malicious_detections = 0;
    std::int64_t active_quarantine_count = 0;
};

// Owns the AvSuite SQLite database: scan history, detections, signature DB,
// and whitelist/blacklist tables. Single-file, no server -- shared schema used
// from Phase 1 onward so a later dashboard can read real history without a
// migration.
class Database {
public:
    static std::unique_ptr<Database> Open(const std::string& path);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    std::int64_t BeginScan(const std::string& target_path, const std::string& scan_type);
    void FinishScan(std::int64_t scan_id);

    void InsertDetection(const avcore::DetectionEvent& event, std::int64_t scan_id = 0);
    std::vector<avcore::DetectionEvent> RecentDetections(int limit = 100);
    void ClearDetections();

    // Backs the dashboard's home/status page -- four COUNT(*) queries
    // rather than fetching full rows just to size() them.
    DbStats GetStats();

    void UpsertSignature(const SignatureRecord& record);
    std::optional<SignatureRecord> LookupSignatureByHash(const std::string& sha256);
    std::vector<SignatureRecord> ListAllSignatures();

    // Tracks which signature DB version this database last applied from the
    // update server, so the client only re-fetches when the server's
    // manifest reports something newer.
    std::string GetAppliedSignatureDbVersion();
    void SetAppliedSignatureDbVersion(const std::string& version);

    bool IsHashWhitelisted(const std::string& sha256);
    bool IsPathWhitelisted(const std::string& path);
    bool IsHashBlacklisted(const std::string& sha256);

    void AddHashToWhitelist(const std::string& sha256, const std::string& note);
    void AddPathToWhitelist(const std::string& path, const std::string& note);
    void AddHashToBlacklist(const std::string& sha256, const std::string& note);
    void RemoveHashFromWhitelist(const std::string& sha256);
    void RemoveHashFromBlacklist(const std::string& sha256);

    // Used by Engine::ExportHashLists/ImportHashLists -- path-based whitelist
    // entries are deliberately excluded since a local path isn't portable
    // across machines.
    std::vector<HashListEntry> ListWhitelistHashes();
    std::vector<HashListEntry> ListBlacklistHashes();

    std::int64_t InsertQuarantineRecord(const avcore::QuarantineRecord& record);
    std::optional<avcore::QuarantineRecord> GetQuarantineRecord(std::int64_t id);
    std::vector<avcore::QuarantineRecord> ListQuarantine(bool include_restored = false);
    void MarkQuarantineRestored(std::int64_t id);
    bool DeleteQuarantineRecord(std::int64_t id);

private:
    explicit Database(sqlite3* handle);
    void CreateSchema();
    void SeedDefaultSignatures();

    sqlite3* db_;
};

} // namespace avstorage
