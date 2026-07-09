#include "avstaticscan/hash_signature.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace avstaticscan {

namespace {

constexpr size_t kReadChunkBytes = 1 << 16;

std::string DigestToHex(const std::vector<UCHAR>& digest) {
    std::ostringstream oss;
    for (UCHAR byte : digest) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

} // namespace

std::optional<std::string> ComputeSha256(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return std::nullopt;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return std::nullopt;

    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    std::vector<char> buffer(kReadChunkBytes);
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) break;
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(bytes_read), 0);
    }

    constexpr DWORD kDigestSize = 32; // SHA-256
    std::vector<UCHAR> digest(kDigestSize);
    const bool finished = BCryptFinishHash(hash, digest.data(), kDigestSize, 0) == 0;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!finished) return std::nullopt;

    return DigestToHex(digest);
}

std::optional<std::string> ComputeSha256Bytes(const std::string& data) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return std::nullopt;

    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()),
                   0);

    constexpr DWORD kDigestSize = 32; // SHA-256
    std::vector<UCHAR> digest(kDigestSize);
    const bool finished = BCryptFinishHash(hash, digest.data(), kDigestSize, 0) == 0;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!finished) return std::nullopt;

    return DigestToHex(digest);
}

std::optional<avcore::DetectionEvent> CheckHashSignature(const std::string& path, avstorage::Database& db) {
    const auto hash = ComputeSha256(path);
    if (!hash) return std::nullopt;
    if (db.IsHashWhitelisted(*hash)) return std::nullopt;

    const auto record = db.LookupSignatureByHash(*hash);
    const bool blacklisted = db.IsHashBlacklisted(*hash);
    if (!record && !blacklisted) return std::nullopt;

    avcore::DetectionEvent detection;
    detection.rule_id = record ? ("SIG.HASH." + hash->substr(0, 12)) : "SIG.HASH.BLACKLISTED";
    detection.source = "hash_signature";
    detection.severity = record ? record->severity : avcore::Severity::Malicious;
    detection.target_path = path;
    detection.evidence = record ? ("Matches known signature: " + record->malware_name)
                                 : "File hash present in manual blacklist.";
    return detection;
}

} // namespace avstaticscan
