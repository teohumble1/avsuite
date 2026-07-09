#include <cstdio>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "avstaticscan/hash_signature.hpp"
#include "avstorage/database.hpp"

namespace {

std::string MakeTempFile(const std::string& name, const std::string& content) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary);
    out << content;
    out.close();
    return path.string();
}

} // namespace

TEST(HashSignatureTest, ComputeSha256MatchesKnownVector) {
    // SHA-256("abc") is a well-known published test vector.
    const std::string path = MakeTempFile("avsuite_test_abc.txt", "abc");
    const auto hash = avstaticscan::ComputeSha256(path);
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(*hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::remove(path.c_str());
}

TEST(HashSignatureTest, ReturnsNulloptForMissingFile) {
    EXPECT_FALSE(avstaticscan::ComputeSha256("C:\\does\\not\\exist.bin").has_value());
}

TEST(HashSignatureTest, FlagsKnownSignatureHash) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string path = MakeTempFile("avsuite_test_known_bad.txt", "totally evil content");
    const auto hash = avstaticscan::ComputeSha256(path);
    ASSERT_TRUE(hash.has_value());

    db->UpsertSignature({*hash, "Test.Malware.Synthetic", avcore::Severity::Malicious});

    const auto detection = avstaticscan::CheckHashSignature(path, *db);
    ASSERT_TRUE(detection.has_value());
    EXPECT_EQ(detection->severity, avcore::Severity::Malicious);
    std::remove(path.c_str());
}

TEST(HashSignatureTest, WhitelistShortCircuitsBeforeSignatureLookup) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string path = MakeTempFile("avsuite_test_whitelisted.txt", "this would normally be flagged");
    const auto hash = avstaticscan::ComputeSha256(path);
    ASSERT_TRUE(hash.has_value());

    db->UpsertSignature({*hash, "Test.Malware.ShouldBeIgnored", avcore::Severity::Malicious});
    db->AddHashToWhitelist(*hash, "known-good test fixture");

    const auto detection = avstaticscan::CheckHashSignature(path, *db);
    EXPECT_FALSE(detection.has_value());
    std::remove(path.c_str());
}

TEST(HashSignatureTest, FreshDatabaseHasEicarSignatureSeeded) {
    // Verified against the database layer directly (no file I/O) so this
    // test never writes the actual EICAR string to disk -- real-time AV on
    // the build machine (Windows Defender included) will quarantine it on
    // sight, which would make a file-based version of this test flaky.
    auto db = avstorage::Database::Open(":memory:");
    const auto record =
        db->LookupSignatureByHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->malware_name, "Test.EICAR-Standard-AV-Test-File");
    EXPECT_EQ(record->severity, avcore::Severity::Malicious);
}

TEST(HashSignatureTest, CleanFileProducesNoDetection) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string path = MakeTempFile("avsuite_test_clean.txt", "nothing interesting here");

    const auto detection = avstaticscan::CheckHashSignature(path, *db);
    EXPECT_FALSE(detection.has_value());
    std::remove(path.c_str());
}
