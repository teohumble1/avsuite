#pragma once

#include <optional>
#include <string>

#include "avcore/detection_event.hpp"
#include "avstorage/database.hpp"

namespace avstaticscan {

// SHA-256 via Windows CNG (BCrypt) -- streamed, no file-size cap needed.
std::optional<std::string> ComputeSha256(const std::string& path);

// SHA-256 of an in-memory buffer -- used to verify downloaded update payloads.
std::optional<std::string> ComputeSha256Bytes(const std::string& data);

// Hashes `path` and checks it against avstorage's signature/blacklist tables.
// Whitelisted hashes short-circuit to nullopt before any signature lookup.
std::optional<avcore::DetectionEvent> CheckHashSignature(const std::string& path, avstorage::Database& db);

} // namespace avstaticscan
