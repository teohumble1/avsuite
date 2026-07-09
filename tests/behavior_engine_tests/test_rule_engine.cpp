#include <cstdlib>
#include <string>

#include <gtest/gtest.h>

#include "avbehavior/rule_engine.hpp"

namespace {

using avbehavior::ProcessEvent;
using avbehavior::RuleEngine;

bool HasRule(const std::vector<avcore::DetectionEvent>& detections, const std::string& rule_id) {
    for (const auto& d : detections) {
        if (d.rule_id == rule_id) return true;
    }
    return false;
}

std::string TempDir() {
    const char* temp = std::getenv("TEMP");
    return temp ? std::string(temp) : std::string("C:\\Users\\Default\\AppData\\Local\\Temp");
}

} // namespace

TEST(RuleEngineTest, FlagsLolbinCertutilDecode) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent event;
    event.process_id = 100;
    event.parent_process_id = 1;
    event.image_path = "C:\\Windows\\System32\\certutil.exe";
    event.command_line = "certutil.exe -decode payload.txt out.exe";

    const auto detections = engine.OnProcessCreate(event);
    EXPECT_TRUE(HasRule(detections, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(RuleEngineTest, DoesNotFlagBenignCertutilUsage) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent event;
    event.process_id = 101;
    event.parent_process_id = 1;
    event.image_path = "C:\\Windows\\System32\\certutil.exe";
    event.command_line = "certutil.exe -hashfile document.pdf SHA256";

    const auto detections = engine.OnProcessCreate(event);
    EXPECT_FALSE(HasRule(detections, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(RuleEngineTest, OfficeSpawningPowershellIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent office;
    office.process_id = 10;
    office.parent_process_id = 1;
    office.image_path = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
    engine.OnProcessCreate(office);

    ProcessEvent child;
    child.process_id = 11;
    child.parent_process_id = 10;
    child.image_path = "C:\\Windows\\System32\\powershell.exe";
    child.command_line = "powershell.exe -nop -enc SQBFAFgA...";

    const auto detections = engine.OnProcessCreate(child);
    bool found_malicious = false;
    for (const auto& d : detections) {
        if (d.rule_id == "BEH.OFFICE_SPAWNS_SHELL") {
            found_malicious = (d.severity == avcore::Severity::Malicious);
        }
    }
    EXPECT_TRUE(found_malicious);
}

TEST(RuleEngineTest, DoesNotFlagUnrelatedParentChild) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent explorer;
    explorer.process_id = 20;
    explorer.parent_process_id = 1;
    explorer.image_path = "C:\\Windows\\explorer.exe";
    engine.OnProcessCreate(explorer);

    ProcessEvent child;
    child.process_id = 21;
    child.parent_process_id = 20;
    child.image_path = "C:\\Windows\\System32\\powershell.exe";
    child.command_line = "powershell.exe -File C:\\scripts\\backup.ps1";

    const auto detections = engine.OnProcessCreate(child);
    EXPECT_FALSE(HasRule(detections, "BEH.OFFICE_SPAWNS_SHELL"));
}

TEST(RuleEngineTest, TempSpawnFlaggedWithoutKnownParent) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent event;
    event.process_id = 30;
    event.parent_process_id = 2; // not registered in the tree
    event.image_path = TempDir() + "\\dropper_payload.exe";

    const auto detections = engine.OnProcessCreate(event);
    EXPECT_TRUE(HasRule(detections, "BEH.TEMP_APPDATA_SPAWN"));
}

TEST(RuleEngineTest, TempSpawnAllowedForMsiexecParent) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent msiexec;
    msiexec.process_id = 40;
    msiexec.parent_process_id = 1;
    msiexec.image_path = "C:\\Windows\\System32\\msiexec.exe";
    engine.OnProcessCreate(msiexec);

    ProcessEvent installer_temp;
    installer_temp.process_id = 41;
    installer_temp.parent_process_id = 40;
    installer_temp.image_path = TempDir() + "\\{installer-guid}\\setup_helper.exe";

    const auto detections = engine.OnProcessCreate(installer_temp);
    EXPECT_FALSE(HasRule(detections, "BEH.TEMP_APPDATA_SPAWN"));
}

TEST(RuleEngineTest, UnsignedTempExecFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent event;
    event.process_id = 50;
    event.parent_process_id = 2;
    // File need not exist for this check -- IsAuthenticodeSigned simply fails
    // closed (treated as unsigned) for a missing/unverifiable file.
    event.image_path = TempDir() + "\\definitely_not_signed.exe";

    const auto detections = engine.OnProcessCreate(event);
    EXPECT_TRUE(HasRule(detections, "BEH.UNSIGNED_TEMP_EXEC"));
}

TEST(RuleEngineTest, SignedSystemBinaryNotFlaggedAsUnsigned) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    ProcessEvent event;
    event.process_id = 51;
    event.parent_process_id = 2;
    event.image_path = "C:\\Windows\\System32\\notepad.exe"; // not under a user-writable dir at all

    const auto detections = engine.OnProcessCreate(event);
    EXPECT_FALSE(HasRule(detections, "BEH.UNSIGNED_TEMP_EXEC"));
}
