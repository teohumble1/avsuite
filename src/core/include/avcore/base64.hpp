#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace avcore {

// Standard (RFC 4648) base64 with '=' padding. Used for shipping raw binary
// (Ed25519 signatures, hashes) inside JSON manifests.
std::string Base64Encode(const std::uint8_t* data, std::size_t len);

// Returns false (leaving out unspecified) if the input isn't valid base64.
bool Base64Decode(const std::string& in, std::vector<std::uint8_t>& out);

} // namespace avcore
