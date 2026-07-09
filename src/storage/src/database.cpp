#include "avstorage/database.hpp"

#include <sqlite3.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace avstorage {

namespace {

// Minimal RAII wrapper around a prepared statement so every query below gets
// automatic cleanup even on early return / exception.
class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_prepare_v2 failed: ") + sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(stmt_); }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    void BindText(int index, const std::string& value) {
        sqlite3_bind_text(stmt_, index, value.c_str(), -1, SQLITE_TRANSIENT);
    }
    void BindInt64(int index, std::int64_t value) { sqlite3_bind_int64(stmt_, index, value); }
    void BindInt(int index, int value) { sqlite3_bind_int(stmt_, index, value); }

    bool Step() {
        int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw std::runtime_error(std::string("sqlite3_step failed: ") + sqlite3_errmsg(db_));
    }

    std::string ColumnText(int index) {
        const unsigned char* text = sqlite3_column_text(stmt_, index);
        return text ? reinterpret_cast<const char*>(text) : std::string();
    }
    int ColumnInt(int index) { return sqlite3_column_int(stmt_, index); }
    std::int64_t ColumnInt64(int index) { return sqlite3_column_int64(stmt_, index); }

    sqlite3_stmt* raw() { return stmt_; }

private:
    sqlite3* db_;
    sqlite3_stmt* stmt_ = nullptr;
};

std::string TimePointToIso8601(std::chrono::system_clock::time_point tp) {
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::chrono::system_clock::time_point Iso8601ToTimePoint(const std::string& s) {
    std::tm tm{};
    std::istringstream iss(s);
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (iss.fail()) {
        return std::chrono::system_clock::now();
    }
    return std::chrono::system_clock::from_time_t(_mkgmtime(&tm));
}

void Exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string message = err ? err : "unknown sqlite error";
        sqlite3_free(err);
        throw std::runtime_error("sqlite3_exec failed: " + message);
    }
}

} // namespace

Database::Database(sqlite3* handle) : db_(handle) {}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

std::unique_ptr<Database> Database::Open(const std::string& path) {
    sqlite3* handle = nullptr;
    if (sqlite3_open(path.c_str(), &handle) != SQLITE_OK) {
        std::string msg = handle ? sqlite3_errmsg(handle) : "unknown error";
        if (handle) sqlite3_close(handle);
        throw std::runtime_error("failed to open database '" + path + "': " + msg);
    }
    Exec(handle, "PRAGMA journal_mode=WAL;");
    Exec(handle, "PRAGMA foreign_keys=ON;");

    auto database = std::unique_ptr<Database>(new Database(handle));
    database->CreateSchema();
    return database;
}

void Database::CreateSchema() {
    Exec(db_, R"sql(
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_path TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT
        );
    )sql");

    Exec(db_, R"sql(
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            rule_id TEXT NOT NULL,
            source TEXT NOT NULL,
            severity INTEGER NOT NULL,
            target_path TEXT NOT NULL,
            process_id INTEGER NOT NULL DEFAULT 0,
            parent_process_id INTEGER NOT NULL DEFAULT 0,
            evidence TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
    )sql");

    Exec(db_, R"sql(
        CREATE TABLE IF NOT EXISTS signatures (
            sha256 TEXT PRIMARY KEY,
            malware_name TEXT NOT NULL,
            severity INTEGER NOT NULL,
            added_at TEXT NOT NULL
        );
    )sql");

    Exec(db_, "CREATE TABLE IF NOT EXISTS whitelist_hash (sha256 TEXT PRIMARY KEY, note TEXT);");
    Exec(db_, "CREATE TABLE IF NOT EXISTS whitelist_path (path TEXT PRIMARY KEY, note TEXT);");
    Exec(db_, "CREATE TABLE IF NOT EXISTS blacklist_hash (sha256 TEXT PRIMARY KEY, note TEXT);");
    Exec(db_, "CREATE TABLE IF NOT EXISTS update_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);");

    Exec(db_, R"sql(
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            evidence TEXT,
            quarantined_at TEXT NOT NULL,
            restored INTEGER NOT NULL DEFAULT 0
        );
    )sql");

    SeedDefaultSignatures();
}

void Database::SeedDefaultSignatures() {
    // The EICAR Standard Anti-Virus Test File is the industry-standard,
    // intentionally-benign string every AV product recognizes for testing --
    // it is not executable malware. Seeding its hash here means a fresh
    // database always has at least one real, verifiable signature, without
    // shipping any actual malware sample. See https://www.eicar.org/.
    UpsertSignature({
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "Test.EICAR-Standard-AV-Test-File",
        avcore::Severity::Malicious,
    });
}

std::int64_t Database::BeginScan(const std::string& target_path, const std::string& scan_type) {
    Statement stmt(db_, "INSERT INTO scans (target_path, scan_type, started_at) VALUES (?, ?, ?);");
    stmt.BindText(1, target_path);
    stmt.BindText(2, scan_type);
    stmt.BindText(3, TimePointToIso8601(std::chrono::system_clock::now()));
    stmt.Step();
    return sqlite3_last_insert_rowid(db_);
}

void Database::FinishScan(std::int64_t scan_id) {
    Statement stmt(db_, "UPDATE scans SET finished_at = ? WHERE id = ?;");
    stmt.BindText(1, TimePointToIso8601(std::chrono::system_clock::now()));
    stmt.BindInt64(2, scan_id);
    stmt.Step();
}

void Database::InsertDetection(const avcore::DetectionEvent& event, std::int64_t scan_id) {
    Statement stmt(db_, R"sql(
        INSERT INTO detections (scan_id, rule_id, source, severity, target_path, process_id, parent_process_id, evidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    )sql");
    if (scan_id != 0) {
        stmt.BindInt64(1, scan_id);
    }
    stmt.BindText(2, event.rule_id);
    stmt.BindText(3, event.source);
    stmt.BindInt(4, static_cast<int>(event.severity));
    stmt.BindText(5, event.target_path);
    stmt.BindInt(6, static_cast<int>(event.process_id));
    stmt.BindInt(7, static_cast<int>(event.parent_process_id));
    stmt.BindText(8, event.evidence);
    stmt.BindText(9, TimePointToIso8601(event.timestamp));
    stmt.Step();
}

void Database::ClearDetections() {
    Exec(db_, "DELETE FROM detections;");
    Exec(db_, "DELETE FROM scans;");
}

namespace {

std::int64_t CountRows(sqlite3* db, const char* sql) {
    Statement stmt(db, sql);
    return stmt.Step() ? stmt.ColumnInt64(0) : 0;
}

} // namespace

DbStats Database::GetStats() {
    // Single round-trip with scalar sub-selects instead of 4 separate queries.
    const std::string sql =
        "SELECT "
        "  (SELECT COUNT(*) FROM scans),"
        "  (SELECT COUNT(*) FROM detections),"
        "  (SELECT COUNT(*) FROM detections WHERE severity = " +
        std::to_string(static_cast<int>(avcore::Severity::Malicious)) + "),"
        "  (SELECT COUNT(*) FROM quarantine WHERE restored = 0);";
    Statement stmt(db_, sql.c_str());
    DbStats stats;
    if (stmt.Step()) {
        stats.total_scans             = stmt.ColumnInt64(0);
        stats.total_detections        = stmt.ColumnInt64(1);
        stats.malicious_detections    = stmt.ColumnInt64(2);
        stats.active_quarantine_count = stmt.ColumnInt64(3);
    }
    return stats;
}

std::vector<avcore::DetectionEvent> Database::RecentDetections(int limit) {
    Statement stmt(db_, R"sql(
        SELECT rule_id, source, severity, target_path, process_id, parent_process_id, evidence, timestamp
        FROM detections ORDER BY id DESC LIMIT ?;
    )sql");
    stmt.BindInt(1, limit);

    std::vector<avcore::DetectionEvent> results;
    while (stmt.Step()) {
        avcore::DetectionEvent event;
        event.rule_id = stmt.ColumnText(0);
        event.source = stmt.ColumnText(1);
        event.severity = static_cast<avcore::Severity>(stmt.ColumnInt(2));
        event.target_path = stmt.ColumnText(3);
        event.process_id = static_cast<std::uint32_t>(stmt.ColumnInt(4));
        event.parent_process_id = static_cast<std::uint32_t>(stmt.ColumnInt(5));
        event.evidence = stmt.ColumnText(6);
        event.timestamp = Iso8601ToTimePoint(stmt.ColumnText(7));
        results.push_back(std::move(event));
    }
    return results;
}

void Database::UpsertSignature(const SignatureRecord& record) {
    Statement stmt(db_, R"sql(
        INSERT INTO signatures (sha256, malware_name, severity, added_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET malware_name = excluded.malware_name, severity = excluded.severity;
    )sql");
    stmt.BindText(1, record.sha256);
    stmt.BindText(2, record.malware_name);
    stmt.BindInt(3, static_cast<int>(record.severity));
    stmt.BindText(4, TimePointToIso8601(std::chrono::system_clock::now()));
    stmt.Step();
}

std::optional<SignatureRecord> Database::LookupSignatureByHash(const std::string& sha256) {
    Statement stmt(db_, "SELECT sha256, malware_name, severity FROM signatures WHERE sha256 = ?;");
    stmt.BindText(1, sha256);
    if (!stmt.Step()) return std::nullopt;

    SignatureRecord record;
    record.sha256 = stmt.ColumnText(0);
    record.malware_name = stmt.ColumnText(1);
    record.severity = static_cast<avcore::Severity>(stmt.ColumnInt(2));
    return record;
}

std::vector<SignatureRecord> Database::ListAllSignatures() {
    Statement stmt(db_, "SELECT sha256, malware_name, severity FROM signatures;");
    std::vector<SignatureRecord> records;
    while (stmt.Step()) {
        SignatureRecord record;
        record.sha256 = stmt.ColumnText(0);
        record.malware_name = stmt.ColumnText(1);
        record.severity = static_cast<avcore::Severity>(stmt.ColumnInt(2));
        records.push_back(std::move(record));
    }
    return records;
}

std::string Database::GetAppliedSignatureDbVersion() {
    Statement stmt(db_, "SELECT value FROM update_state WHERE key = 'signature_db_version';");
    if (!stmt.Step()) return std::string();
    return stmt.ColumnText(0);
}

void Database::SetAppliedSignatureDbVersion(const std::string& version) {
    Statement stmt(db_, "INSERT OR REPLACE INTO update_state (key, value) VALUES ('signature_db_version', ?);");
    stmt.BindText(1, version);
    stmt.Step();
}

bool Database::IsHashWhitelisted(const std::string& sha256) {
    Statement stmt(db_, "SELECT 1 FROM whitelist_hash WHERE sha256 = ?;");
    stmt.BindText(1, sha256);
    return stmt.Step();
}

bool Database::IsPathWhitelisted(const std::string& path) {
    Statement stmt(db_, "SELECT 1 FROM whitelist_path WHERE path = ?;");
    stmt.BindText(1, path);
    return stmt.Step();
}

bool Database::IsHashBlacklisted(const std::string& sha256) {
    Statement stmt(db_, "SELECT 1 FROM blacklist_hash WHERE sha256 = ?;");
    stmt.BindText(1, sha256);
    return stmt.Step();
}

void Database::AddHashToWhitelist(const std::string& sha256, const std::string& note) {
    Statement stmt(db_, "INSERT OR REPLACE INTO whitelist_hash (sha256, note) VALUES (?, ?);");
    stmt.BindText(1, sha256);
    stmt.BindText(2, note);
    stmt.Step();
}

void Database::AddPathToWhitelist(const std::string& path, const std::string& note) {
    Statement stmt(db_, "INSERT OR REPLACE INTO whitelist_path (path, note) VALUES (?, ?);");
    stmt.BindText(1, path);
    stmt.BindText(2, note);
    stmt.Step();
}

void Database::AddHashToBlacklist(const std::string& sha256, const std::string& note) {
    Statement stmt(db_, "INSERT OR REPLACE INTO blacklist_hash (sha256, note) VALUES (?, ?);");
    stmt.BindText(1, sha256);
    stmt.BindText(2, note);
    stmt.Step();
}

void Database::RemoveHashFromWhitelist(const std::string& sha256) {
    Statement stmt(db_, "DELETE FROM whitelist_hash WHERE sha256 = ?;");
    stmt.BindText(1, sha256);
    stmt.Step();
}

void Database::RemoveHashFromBlacklist(const std::string& sha256) {
    Statement stmt(db_, "DELETE FROM blacklist_hash WHERE sha256 = ?;");
    stmt.BindText(1, sha256);
    stmt.Step();
}

namespace {

std::vector<HashListEntry> ListHashes(sqlite3* db, const char* table) {
    Statement stmt(db, (std::string("SELECT sha256, note FROM ") + table + ";").c_str());
    std::vector<HashListEntry> entries;
    while (stmt.Step()) {
        entries.push_back({stmt.ColumnText(0), stmt.ColumnText(1)});
    }
    return entries;
}

} // namespace

std::vector<HashListEntry> Database::ListWhitelistHashes() { return ListHashes(db_, "whitelist_hash"); }

std::vector<HashListEntry> Database::ListBlacklistHashes() { return ListHashes(db_, "blacklist_hash"); }

std::int64_t Database::InsertQuarantineRecord(const avcore::QuarantineRecord& record) {
    Statement stmt(db_, R"sql(
        INSERT INTO quarantine (original_path, quarantine_path, sha256, rule_id, evidence, quarantined_at, restored)
        VALUES (?, ?, ?, ?, ?, ?, 0);
    )sql");
    stmt.BindText(1, record.original_path);
    stmt.BindText(2, record.quarantine_path);
    stmt.BindText(3, record.sha256);
    stmt.BindText(4, record.rule_id);
    stmt.BindText(5, record.evidence);
    stmt.BindText(6, TimePointToIso8601(record.quarantined_at));
    stmt.Step();
    return sqlite3_last_insert_rowid(db_);
}

namespace {

avcore::QuarantineRecord QuarantineRecordFromRow(Statement& stmt) {
    avcore::QuarantineRecord record;
    record.id = stmt.ColumnInt64(0);
    record.original_path = stmt.ColumnText(1);
    record.quarantine_path = stmt.ColumnText(2);
    record.sha256 = stmt.ColumnText(3);
    record.rule_id = stmt.ColumnText(4);
    record.evidence = stmt.ColumnText(5);
    record.quarantined_at = Iso8601ToTimePoint(stmt.ColumnText(6));
    record.restored = stmt.ColumnInt(7) != 0;
    return record;
}

constexpr const char* kQuarantineColumns =
    "id, original_path, quarantine_path, sha256, rule_id, evidence, quarantined_at, restored";

} // namespace

std::optional<avcore::QuarantineRecord> Database::GetQuarantineRecord(std::int64_t id) {
    Statement stmt(db_, (std::string("SELECT ") + kQuarantineColumns + " FROM quarantine WHERE id = ?;").c_str());
    stmt.BindInt64(1, id);
    if (!stmt.Step()) return std::nullopt;
    return QuarantineRecordFromRow(stmt);
}

std::vector<avcore::QuarantineRecord> Database::ListQuarantine(bool include_restored) {
    const std::string sql = std::string("SELECT ") + kQuarantineColumns + " FROM quarantine" +
                             (include_restored ? "" : " WHERE restored = 0") + " ORDER BY id DESC;";
    Statement stmt(db_, sql.c_str());

    std::vector<avcore::QuarantineRecord> results;
    while (stmt.Step()) {
        results.push_back(QuarantineRecordFromRow(stmt));
    }
    return results;
}

void Database::MarkQuarantineRestored(std::int64_t id) {
    Statement stmt(db_, "UPDATE quarantine SET restored = 1 WHERE id = ?;");
    stmt.BindInt64(1, id);
    stmt.Step();
}

bool Database::DeleteQuarantineRecord(std::int64_t id) {
    Statement stmt(db_, "DELETE FROM quarantine WHERE id = ?;");
    stmt.BindInt64(1, id);
    stmt.Step();
    return sqlite3_changes(db_) > 0;
}

} // namespace avstorage
