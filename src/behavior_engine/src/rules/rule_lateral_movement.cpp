#include "rules/rule_lateral_movement.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

using avcore::Severity;

struct LMPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
    Severity    severity;
};

// Severity tiering: built-in remote-administration tools (PsExec, WinRM/PSSession,
// wmic /node:, winrs, schtasks /s) are used every day by legitimate admins, so
// they are Suspicious rather than Malicious. Dedicated offensive tooling
// (Impacket *.py, CrackMapExec, evil-winrm) is Malicious. `net use` is narrowed
// to administrative shares (C$/ADMIN$/IPC$) -- mapping a normal file share is
// benign and no longer flagged.
constexpr LMPattern kPatterns[] = {
    // Built-in remote admin -- dual-use
    {"psexec.exe",    "\\\\",          "PsExec remote execution via UNC path", Severity::Suspicious},
    {"psexec64.exe",  "\\\\",          "PsExec64 remote execution",            Severity::Suspicious},
    {"psexesvc.exe",  "",              "PsExec service (psexesvc) present on target", Severity::Suspicious},
    {"wmic.exe",      "/node:",        "wmic remote process execution via /node:", Severity::Suspicious},
    {"winrs.exe",     "-r:",           "winrs remote shell execution",         Severity::Suspicious},
    {"winrs.exe",     "/r:",           "winrs remote shell execution",         Severity::Suspicious},
    {"powershell.exe","invoke-command","PowerShell Invoke-Command remoting",   Severity::Suspicious},
    {"powershell.exe","new-pssession", "PowerShell New-PSSession (WinRM)",     Severity::Suspicious},
    {"powershell.exe","enter-pssession","PowerShell Enter-PSSession (WinRM)",  Severity::Suspicious},
    {"pwsh.exe",      "invoke-command","pwsh Invoke-Command remoting",         Severity::Suspicious},
    {"schtasks.exe",  "/s ",          "schtasks remote scheduled task creation", Severity::Suspicious},
    // net use to administrative shares (lateral movement targets, not file shares)
    {"net.exe",       "\\admin$",     "net use mounting ADMIN$ share (lateral movement)", Severity::Suspicious},
    {"net.exe",       "\\ipc$",       "net use mounting IPC$ share (lateral movement)",   Severity::Suspicious},
    {"net.exe",       "\\c$",         "net use mounting C$ admin share (lateral movement)", Severity::Suspicious},
    {"at.exe",        "\\\\",         "at.exe remote job scheduling (legacy lateral movement)", Severity::Suspicious},
    // Dedicated offensive tooling -- Malicious on mere presence
    {"wmiexec.py",    "",             "Impacket wmiexec execution",            Severity::Malicious},
    {"smbexec.py",    "",             "Impacket smbexec execution",            Severity::Malicious},
    {"atexec.py",     "",             "Impacket atexec execution",             Severity::Malicious},
    {"dcomexec.py",   "",             "Impacket dcomexec execution",           Severity::Malicious},
    {"crackmapexec.exe","",           "CrackMapExec lateral movement tool",    Severity::Malicious},
    {"evil-winrm.exe", "",            "evil-winrm remote shell tool",          Severity::Malicious},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleLateralMovement::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string cmd_lower  = avcore::ToLowerAscii(event.command_line);

    for (const auto& pat : kPatterns) {
        if (image_name != pat.binary) continue;
        const std::string trigger(pat.arg_substring);
        if (!trigger.empty() && cmd_lower.find(trigger) == std::string::npos) continue;

        avcore::DetectionEvent det;
        det.rule_id           = Id();
        det.source            = "behavior_engine";
        det.severity          = pat.severity;
        det.target_path       = event.image_path;
        det.process_id        = event.process_id;
        det.parent_process_id = event.parent_process_id;
        det.evidence          = std::string(pat.description) + ". Command line: " + event.command_line;
        return det;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
