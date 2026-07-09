#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "avcore/quarantine_record.hpp"
#include "avstorage/database.hpp"

namespace avremediation {

// Moves `path` into `quarantine_directory` (created if missing, renamed to
// "<sha256>.quar" so it can't be double-clicked or run by its original
// extension) and records the move in `db`. Never deletes outright --
// hash/YARA detections can be wrong, and quarantine is meant to be a
// reversible holding area, not a destructive action.
//
// Returns nullopt (leaving the original file untouched) if the move itself
// fails -- e.g. the file is open elsewhere, already gone, or the quarantine
// directory isn't writable. This mirrors the rest of the engine's fail-safe
// style: a remediation failure is reported, not thrown.
std::optional<avcore::QuarantineRecord> Quarantine(const std::string& path, const std::string& sha256,
                                                     const std::string& rule_id, const std::string& evidence,
                                                     const std::string& quarantine_directory, avstorage::Database& db);

// Moves a previously quarantined file back to its original location and
// marks the record restored. Fails (returns false) if the record doesn't
// exist, was already restored, the quarantined file is missing, or
// something now occupies the original path -- restoring never overwrites.
bool Restore(std::int64_t quarantine_id, avstorage::Database& db);

// Permanently deletes a quarantined file (the .quar copy, not the original --
// that was already moved away by Quarantine()) and removes its DB record.
// Unlike Quarantine()/Restore(), this is genuinely destructive and
// irreversible -- callers (CLI/GUI) should confirm with the user first.
bool Delete(std::int64_t quarantine_id, avstorage::Database& db);

} // namespace avremediation
