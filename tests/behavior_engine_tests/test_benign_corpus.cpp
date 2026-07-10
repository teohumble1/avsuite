// Benign corpus harness.
//
// The README states the hardest, unsolved part of this project is false-positive
// tuning ("UNKNOWN, likely HIGH" FP rate; "needs a 1M+ benign corpus"). This test
// turns that abstract claim into a concrete, measurable regression gate: it runs a
// curated set of *legitimate* command lines -- the kind produced by installers,
// admin scripts, dev tooling and Windows built-ins -- through the real rule engine
// and measures how the behavior rules react.
//
// Two guarantees are enforced:
//   1. HARD GATE: no benign sample may ever produce a **Malicious** verdict. A
//      confirmed-malware verdict on legitimate activity is the worst failure mode
//      (it auto-quarantines real user files), so it must be zero.
//   2. Samples marked `pure_benign` must produce **no detection at all**.
//
// Dual-use samples (silent installs, service/auto-start creation, remote admin)
// are allowed to surface as *Suspicious* -- that is the intended "worth noting"
// tier, not a false positive. The test also prints the observed Suspicious rate so
// the number the README calls "UNKNOWN" becomes an actual, tracked metric.

#include <iostream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "avbehavior/rule_engine.hpp"

namespace {

using avbehavior::ProcessEvent;
using avbehavior::RuleEngine;

struct BenignSample {
    const char* image;        // full image path
    const char* command_line; // realistic legitimate invocation
    bool        pure_benign;  // true => must produce ZERO detections;
                              // false => dual-use, Suspicious is acceptable (Malicious never is)
    const char* note;
};

// A small but realistic corpus. Every entry is something a normal Windows machine
// runs routinely. None of it is malicious.
const std::vector<BenignSample> kCorpus = {
    // ---- Pure benign: should produce no detection whatsoever ----
    {"C:\\Windows\\explorer.exe", "explorer.exe C:\\Users\\Public\\Documents", true, "open a folder"},
    {"C:\\Program Files\\Git\\cmd\\git.exe", "git.exe clone https://github.com/foo/bar.git", true, "git clone"},
    {"C:\\Program Files\\nodejs\\node.exe", "node.exe server.js", true, "run a node server"},
    {"C:\\Python311\\python.exe", "python.exe manage.py runserver", true, "run a python app"},
    {"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --profile-directory=Default", true, "launch browser"},
    {"C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe --new-window", true, "launch VS Code"},
    {"C:\\Program Files\\dotnet\\dotnet.exe", "dotnet.exe build -c Release", true, "dotnet build"},
    {"C:\\Program Files\\MSBuild\\msbuild.exe", "msbuild.exe MyApp.sln /p:Configuration=Release", true, "msbuild"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-Process lsass", true, "admin: is lsass running"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-WmiObject Win32_OperatingSystem", true, "inventory query"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-Service -Name wuauserv", true, "service query"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Remove-Item -Recurse -Force C:\\Temp\\build", true, "cleanup"},
    {"C:\\Windows\\System32\\reg.exe", "reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\"", true, "registry read"},
    {"C:\\Windows\\System32\\sc.exe", "sc.exe query wuauserv", true, "service query"},
    {"C:\\Windows\\System32\\schtasks.exe", "schtasks.exe /query /fo LIST", true, "list scheduled tasks"},
    {"C:\\Windows\\System32\\net.exe", "net.exe use Z: \\\\fileserver\\Documents /persistent:yes", true, "map a normal file share"},
    {"C:\\Windows\\System32\\certutil.exe", "certutil.exe -hashfile installer.exe SHA256", true, "hash a file"},
    {"C:\\Windows\\System32\\wbem\\wmic.exe", "wmic.exe cpu get name", true, "hardware query"},
    {"C:\\Windows\\System32\\wbem\\wmic.exe", "wmic.exe process list /format:list", true, "process list"},
    {"C:\\Windows\\System32\\makecab.exe", "makecab.exe /D CompressionType=LZX out.cab in.dir", true, "make a cabinet"},
    {"C:\\Windows\\System32\\attrib.exe", "attrib.exe +a C:\\Build\\out.txt", true, "set archive bit"},
    {"C:\\Windows\\System32\\icacls.exe", "icacls.exe \"C:\\ProgramData\\App\" /grant \"Users:(OI)(CI)F\"", true, "grant Users (not Everyone)"},
    {"C:\\Windows\\System32\\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", true, "open a control panel"},

    // ---- Dual-use: Suspicious is acceptable, Malicious is not ----
    {"C:\\Windows\\System32\\msiexec.exe", "msiexec.exe /i app.msi /qn /norestart", false, "silent MSI install"},
    {"C:\\Windows\\System32\\reg.exe", "reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v MyApp /d \"C:\\App\\app.exe\" /f", false, "auto-start entry"},
    {"C:\\Windows\\System32\\sc.exe", "sc.exe create MySvc binPath= \"C:\\App\\svc.exe\" start= auto", false, "install a service"},
    {"C:\\Windows\\System32\\schtasks.exe", "schtasks.exe /create /tn \"MyUpdater\" /tr \"C:\\App\\upd.exe\" /sc daily /st 03:00", false, "scheduled task"},
    {"C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s \"C:\\App\\plugin.dll\"", false, "COM registration by installer"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe New-Service -Name MySvc -BinaryPathName \"C:\\App\\svc.exe\"", false, "install a service"},
    {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Invoke-Command -ComputerName srv01 -ScriptBlock { Get-Service }", false, "remote admin"},
    {"C:\\Windows\\System32\\attrib.exe", "attrib.exe -r C:\\Build\\out.txt", false, "clear read-only in a build"},
};

std::string SeverityName(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return "Malicious";
        case avcore::Severity::Suspicious: return "Suspicious";
        default:                            return "Info";
    }
}

} // namespace

TEST(BenignCorpus, NoMaliciousVerdictsAndMeasuredFalsePositiveRate) {
    RuleEngine engine = RuleEngine::WithDefaultRules();

    int total = 0;
    int malicious_fp = 0;      // benign -> Malicious (must be 0)
    int pure_benign_flagged = 0; // pure-benign -> any detection (must be 0)
    int suspicious_hits = 0;   // benign -> Suspicious (informational FP-rate numerator)

    std::uint32_t pid = 9000;
    for (const auto& s : kCorpus) {
        ++total;
        ProcessEvent e;
        e.process_id = pid++;
        e.parent_process_id = 1;
        e.image_path = s.image;
        e.command_line = s.command_line;

        const auto detections = engine.OnProcessCreate(e);

        avcore::Severity worst = avcore::Severity::Info;
        for (const auto& d : detections) {
            if (static_cast<int>(d.severity) > static_cast<int>(worst)) worst = d.severity;
            if (d.severity == avcore::Severity::Malicious) {
                ++malicious_fp;
                ADD_FAILURE() << "MALICIOUS false positive on benign command:\n"
                              << "  " << s.command_line << "\n"
                              << "  rule=" << d.rule_id << " (" << s.note << ")";
            }
        }

        if (worst == avcore::Severity::Suspicious) ++suspicious_hits;

        if (s.pure_benign && !detections.empty()) {
            ++pure_benign_flagged;
            ADD_FAILURE() << "Pure-benign command produced a detection (expected none):\n"
                          << "  " << s.command_line << "\n"
                          << "  worst=" << SeverityName(worst) << " (" << s.note << ")";
        }
    }

    const double susp_rate = total ? (100.0 * suspicious_hits / total) : 0.0;

    std::cout << "\n===== Benign Corpus Report =====\n"
              << "  samples          : " << total << "\n"
              << "  MALICIOUS FPs    : " << malicious_fp << "   (hard gate: must be 0)\n"
              << "  pure-benign flagged: " << pure_benign_flagged << "   (must be 0)\n"
              << "  Suspicious hits  : " << suspicious_hits
              << "   (" << susp_rate << "% -- dual-use 'worth noting', not confirmed bad)\n"
              << "================================\n" << std::endl;

    // Cardinal guarantee: benign activity is never labelled confirmed malware.
    EXPECT_EQ(0, malicious_fp);
    // Pure-benign activity should be entirely silent.
    EXPECT_EQ(0, pure_benign_flagged);
}
