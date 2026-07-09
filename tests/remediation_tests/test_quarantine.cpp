#include <cstdio>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "avremediation/quarantine.hpp"
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

TEST(QuarantineTest, MovesFileAndRecordsEntry) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_move.txt", "synthetic malicious content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record = avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "synthetic evidence",
                                                   quarantine_dir.string(), *db);

    ASSERT_TRUE(record.has_value());
    EXPECT_FALSE(std::filesystem::exists(original));
    EXPECT_TRUE(std::filesystem::exists(record->quarantine_path));
    EXPECT_EQ(record->original_path, original);
    EXPECT_GT(record->id, 0);

    const auto stored = db->GetQuarantineRecord(record->id);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->rule_id, "TEST.RULE");
    EXPECT_FALSE(stored->restored);

    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, ReturnsNulloptForMissingFile) {
    auto db = avstorage::Database::Open(":memory:");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_missing";
    std::filesystem::remove_all(quarantine_dir);

    const auto record = avremediation::Quarantine("C:\\does\\not\\exist.bin", "deadbeef", "TEST.RULE", "evidence",
                                                   quarantine_dir.string(), *db);

    EXPECT_FALSE(record.has_value());
}

TEST(QuarantineTest, RestoreMovesFileBackAndMarksRestored) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_restore.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_restore_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());

    EXPECT_TRUE(avremediation::Restore(record->id, *db));
    EXPECT_TRUE(std::filesystem::exists(original));
    EXPECT_FALSE(std::filesystem::exists(record->quarantine_path));

    const auto stored = db->GetQuarantineRecord(record->id);
    ASSERT_TRUE(stored.has_value());
    EXPECT_TRUE(stored->restored);

    std::remove(original.c_str());
    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, RestoreFailsIfAlreadyRestored) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_double_restore.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_double_restore_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());

    ASSERT_TRUE(avremediation::Restore(record->id, *db));
    EXPECT_FALSE(avremediation::Restore(record->id, *db));

    std::remove(original.c_str());
    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, RestoreFailsIfOriginalPathNowOccupied) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_occupied.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_occupied_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());

    // Something new now lives at the original path -- restore must not clobber it.
    MakeTempFile("avsuite_quarantine_test_occupied.txt", "a different, legitimate file");

    EXPECT_FALSE(avremediation::Restore(record->id, *db));
    EXPECT_TRUE(std::filesystem::exists(record->quarantine_path));

    std::remove(original.c_str());
    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, DeletePermanentlyRemovesFileAndRecord) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_delete.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_delete_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());

    EXPECT_TRUE(avremediation::Delete(record->id, *db));
    EXPECT_FALSE(std::filesystem::exists(record->quarantine_path));
    EXPECT_FALSE(db->GetQuarantineRecord(record->id).has_value());

    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, DeleteFailsForUnknownId) {
    auto db = avstorage::Database::Open(":memory:");
    EXPECT_FALSE(avremediation::Delete(999, *db));
}

TEST(QuarantineTest, DeleteFailsIfAlreadyRestored) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_delete_restored.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_delete_restored_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());
    ASSERT_TRUE(avremediation::Restore(record->id, *db));

    EXPECT_FALSE(avremediation::Delete(record->id, *db));

    std::remove(original.c_str());
    std::filesystem::remove_all(quarantine_dir);
}

TEST(QuarantineTest, ListQuarantineExcludesRestoredByDefault) {
    auto db = avstorage::Database::Open(":memory:");
    const std::string original = MakeTempFile("avsuite_quarantine_test_list.txt", "synthetic content");
    const auto quarantine_dir = std::filesystem::temp_directory_path() / "avsuite_quarantine_test_list_dir";
    std::filesystem::remove_all(quarantine_dir);

    const auto record =
        avremediation::Quarantine(original, "deadbeef", "TEST.RULE", "evidence", quarantine_dir.string(), *db);
    ASSERT_TRUE(record.has_value());

    EXPECT_EQ(db->ListQuarantine(/*include_restored=*/false).size(), 1u);
    ASSERT_TRUE(avremediation::Restore(record->id, *db));
    EXPECT_EQ(db->ListQuarantine(/*include_restored=*/false).size(), 0u);
    EXPECT_EQ(db->ListQuarantine(/*include_restored=*/true).size(), 1u);

    std::remove(original.c_str());
    std::filesystem::remove_all(quarantine_dir);
}

TEST(DatabaseHashListTest, ListWhitelistAndBlacklistHashesRoundtrip) {
    auto db = avstorage::Database::Open(":memory:");
    db->AddHashToWhitelist("aaaa", "known-good tool");
    db->AddHashToBlacklist("bbbb", "known-bad sample");

    const auto whitelist = db->ListWhitelistHashes();
    ASSERT_EQ(whitelist.size(), 1u);
    EXPECT_EQ(whitelist[0].sha256, "aaaa");
    EXPECT_EQ(whitelist[0].note, "known-good tool");

    const auto blacklist = db->ListBlacklistHashes();
    ASSERT_EQ(blacklist.size(), 1u);
    EXPECT_EQ(blacklist[0].sha256, "bbbb");
    EXPECT_EQ(blacklist[0].note, "known-bad sample");
}

TEST(DatabaseHashListTest, ClearDetectionsEmptiesHistory) {
    auto db = avstorage::Database::Open(":memory:");
    avcore::DetectionEvent event;
    event.rule_id = "TEST.RULE";
    event.source = "test";
    event.severity = avcore::Severity::Suspicious;
    event.target_path = "C:\\does\\not\\matter.txt";
    db->InsertDetection(event);

    ASSERT_EQ(db->RecentDetections(10).size(), 1u);
    db->ClearDetections();
    EXPECT_EQ(db->RecentDetections(10).size(), 0u);
}
