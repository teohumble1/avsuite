#include <cstdio>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "avregscan/registry_scanner.hpp"

using avregscan::AutorunEntry;
using avregscan::EvaluateAutorunEntries;
using avregscan::ExtractExecutablePath;

TEST(ExtractExecutablePathTest, HandlesQuotedPath) {
    EXPECT_EQ(ExtractExecutablePath("\"C:\\Program Files\\App\\app.exe\" --flag"),
              "C:\\Program Files\\App\\app.exe");
}

TEST(ExtractExecutablePathTest, HandlesBarePathWithArgs) {
    EXPECT_EQ(ExtractExecutablePath("C:\\Windows\\System32\\svchost.exe -k netsvcs"),
              "C:\\Windows\\System32\\svchost.exe");
}

TEST(ExtractExecutablePathTest, HandlesUnquotedPathContainingSpaces) {
    EXPECT_EQ(ExtractExecutablePath("C:\\Program Files\\Some App\\app.exe -flag"),
              "C:\\Program Files\\Some App\\app.exe");
}

TEST(EvaluateAutorunEntriesTest, DoesNotFlagSignedSystemBinary) {
    AutorunEntry entry;
    entry.location = "HKLM\\...\\Run";
    entry.value_name = "Test";
    entry.raw_value = "C:\\Windows\\System32\\notepad.exe";
    entry.resolved_executable_path = "C:\\Windows\\System32\\notepad.exe";

    const auto detections = EvaluateAutorunEntries({entry});
    EXPECT_TRUE(detections.empty());
}

TEST(EvaluateAutorunEntriesTest, DoesNotFlagSignedBinaryEvenUnderTempDirectory) {
    // Mirrors a very common real-world pattern (Discord/Steam/Roblox-style
    // updater launchers signed by their publisher but installed under
    // AppData) -- location alone must not be enough to flag a signed binary.
    const auto temp_path = std::filesystem::temp_directory_path() / "avsuite_regtest_signed_in_temp.exe";
    std::filesystem::copy_file("C:\\Windows\\System32\\notepad.exe", temp_path,
                                std::filesystem::copy_options::overwrite_existing);

    AutorunEntry entry;
    entry.location = "HKCU\\...\\Run";
    entry.value_name = "SomeVendorUpdater";
    entry.raw_value = temp_path.string();
    entry.resolved_executable_path = temp_path.string();

    const auto detections = EvaluateAutorunEntries({entry});
    EXPECT_TRUE(detections.empty());

    std::remove(temp_path.string().c_str());
}

TEST(EvaluateAutorunEntriesTest, FlagsEntryUnderTempDirectory) {
    const auto temp_path = std::filesystem::temp_directory_path() / "avsuite_regtest_dropper.exe";
    { std::ofstream out(temp_path, std::ios::binary); out << "not a real PE, just needs to exist"; }

    AutorunEntry entry;
    entry.location = "HKCU\\...\\Run";
    entry.value_name = "UpdaterHelper";
    entry.raw_value = temp_path.string();
    entry.resolved_executable_path = temp_path.string();

    const auto detections = EvaluateAutorunEntries({entry});
    ASSERT_EQ(detections.size(), 1u);
    EXPECT_EQ(detections.front().rule_id, "REG.SUSPICIOUS_AUTORUN");

    std::remove(temp_path.string().c_str());
}

TEST(EvaluateAutorunEntriesTest, SkipsOrphanedEntryPointingNowhere) {
    AutorunEntry entry;
    entry.location = "HKLM\\...\\Run";
    entry.value_name = "LeftoverApp";
    entry.raw_value = "C:\\Program Files\\Uninstalled App\\app.exe";
    entry.resolved_executable_path = "C:\\Program Files\\Uninstalled App\\app.exe";

    const auto detections = EvaluateAutorunEntries({entry});
    EXPECT_TRUE(detections.empty());
}

TEST(EvaluateAutorunEntriesTest, SkipsEntryWithUnresolvedPath) {
    AutorunEntry entry;
    entry.location = "HKLM\\...\\Windows";
    entry.value_name = "AppInit_DLLs";
    entry.raw_value = "";
    entry.resolved_executable_path = "";

    const auto detections = EvaluateAutorunEntries({entry});
    EXPECT_TRUE(detections.empty());
}
