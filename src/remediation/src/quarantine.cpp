#include "avremediation/quarantine.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace avremediation {

namespace {

// std::filesystem::rename fails across volumes (e.g. quarantine_directory
// configured on a different drive than the scanned file) -- fall back to a
// copy + remove of the source so quarantine still works in that case.
bool MoveFile(const std::filesystem::path& from, const std::filesystem::path& to) {
    std::error_code ec;
    std::filesystem::rename(from, to, ec);
    if (!ec) return true;

    if (!std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec)) return false;
    std::filesystem::remove(from, ec);
    return !ec; // false if the source could not be removed (file in use, etc.)
}

// Guards restore against an attacker who tampered with a quarantine record's
// original_path (e.g. if the DB is not ACL-locked) to make us drop the malicious
// file into an arbitrary/system location (review #4). Requires an absolute path
// with no ".." traversal, and refuses to write into the Windows directory (incl.
// System32/SysWOW64) or a Startup auto-run folder.
bool IsSafeRestoreTarget(const std::string& p) {
    if (p.empty()) return false;
    std::error_code ec;
    std::filesystem::path path(p);
    if (!path.is_absolute()) return false;
    for (const auto& part : path)
        if (part.string() == "..") return false;

    std::filesystem::path canon = std::filesystem::weakly_canonical(path, ec);
    if (ec) canon = path.lexically_normal();
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    };
    const std::string low = lower(canon.string());

    auto under_env = [&](const char* name) {
        const char* v = std::getenv(name);
        if (!v || !*v) return false;
        const std::string root = lower(v);
        return low.rfind(root, 0) == 0;  // low starts with root
    };
    if (under_env("SystemRoot") || under_env("windir")) return false;  // C:\Windows + System32
    if (low.find("\\start menu\\programs\\startup") != std::string::npos) return false;
    return true;
}

} // namespace

std::optional<avcore::QuarantineRecord> Quarantine(const std::string& path, const std::string& sha256,
                                                     const std::string& rule_id, const std::string& evidence,
                                                     const std::string& quarantine_directory, avstorage::Database& db) {
    std::error_code ec;
    std::filesystem::create_directories(quarantine_directory, ec);

    const std::string quarantine_name = sha256.empty() ? (std::filesystem::path(path).filename().string() + ".quar")
                                                         : (sha256 + ".quar");
    const std::filesystem::path destination = std::filesystem::path(quarantine_directory) / quarantine_name;

    if (!MoveFile(path, destination)) return std::nullopt;

    avcore::QuarantineRecord record;
    record.original_path = path;
    record.quarantine_path = destination.string();
    record.sha256 = sha256;
    record.rule_id = rule_id;
    record.evidence = evidence;
    record.id = db.InsertQuarantineRecord(record);
    return record;
}

bool Restore(std::int64_t quarantine_id, avstorage::Database& db) {
    const auto record = db.GetQuarantineRecord(quarantine_id);
    if (!record || record->restored) return false;
    if (!IsSafeRestoreTarget(record->original_path)) return false;    // review #4: no arbitrary/system write
    if (!std::filesystem::exists(record->quarantine_path)) return false;
    if (std::filesystem::exists(record->original_path)) return false; // never clobber

    std::filesystem::create_directories(std::filesystem::path(record->original_path).parent_path());
    if (!MoveFile(record->quarantine_path, record->original_path)) return false;

    db.MarkQuarantineRestored(quarantine_id);
    return true;
}

bool Delete(std::int64_t quarantine_id, avstorage::Database& db) {
    const auto record = db.GetQuarantineRecord(quarantine_id);
    if (!record || record->restored) return false;

    std::error_code ec;
    std::filesystem::remove(record->quarantine_path, ec);
    if (ec) return false;

    return db.DeleteQuarantineRecord(quarantine_id);
}

} // namespace avremediation
