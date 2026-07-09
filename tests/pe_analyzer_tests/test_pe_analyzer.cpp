#include <cstdio>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "avpe/pe_analyzer.hpp"

namespace {

std::string MakeTempFile(const std::string& name, const std::string& content) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary);
    out << content;
    out.close();
    return path.string();
}

} // namespace

TEST(PeAnalyzerTest, AnalyzesRealSignedSystemBinary) {
    const auto result = avpe::AnalyzeFile("C:\\Windows\\System32\\notepad.exe");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_signed);
    EXPECT_FALSE(result->has_injection_import_combo);
    EXPECT_TRUE(result->packer_section_hits.empty());
}

TEST(PeAnalyzerTest, RejectsPlainTextFile) {
    const std::string path = MakeTempFile("avsuite_test_not_pe.txt", "this is just a text file, not a PE image");
    const auto result = avpe::AnalyzeFile(path);
    EXPECT_FALSE(result.has_value());
    std::remove(path.c_str());
}

TEST(PeAnalyzerTest, RejectsTruncatedMzHeader) {
    // "MZ" magic followed by garbage too short to contain a real DOS header.
    const std::string path = MakeTempFile("avsuite_test_truncated.exe", "MZ\x00\x00garbage");
    const auto result = avpe::AnalyzeFile(path);
    EXPECT_FALSE(result.has_value());
    std::remove(path.c_str());
}

TEST(PeAnalyzerTest, RejectsMissingFile) {
    const auto result = avpe::AnalyzeFile("C:\\this\\path\\does\\not\\exist.exe");
    EXPECT_FALSE(result.has_value());
}

TEST(PeAnalyzerTest, ToDetectionEventsEmptyForCleanResult) {
    avpe::PeAnalysisResult clean;
    clean.is_signed = true;
    clean.max_section_entropy = 5.0;
    clean.has_injection_import_combo = false;

    const auto events = avpe::ToDetectionEvents("C:\\Windows\\System32\\notepad.exe", clean);
    EXPECT_TRUE(events.empty());
}

TEST(PeAnalyzerTest, ToDetectionEventsFlagsInjectionCombo) {
    avpe::PeAnalysisResult result;
    result.is_signed = true;
    result.has_injection_import_combo = true;

    const auto events = avpe::ToDetectionEvents("C:\\some\\file.exe", result);
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.front().rule_id, "PE.INJECTION_IMPORT_COMBO");
}
