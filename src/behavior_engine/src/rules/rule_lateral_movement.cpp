#include "rules/rule_lateral_movement.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct LMPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr LMPattern kPatterns[] = {
    // PsExec variants
    {"psexec.exe",    "\\\\",          "PsExec remote execution via UNC path"},
    {"psexec64.exe",  "\\\\",          "PsExec64 remote execution"},
    {"psexesvc.exe",  "",              "PsExec service (psexesvc) installed on target"},
    // wmic remote execution
    {"wmic.exe",      "/node:",        "wmic remote process execution via /node:"},
    // winrs (Windows Remote Shell)
    {"winrs.exe",     "-r:",           "winrs remote shell execution"},
    {"winrs.exe",     "/r:",           "winrs remote shell execution"},
    // PowerShell remoting / WinRM
    {"powershell.exe","invoke-command","PowerShell Invoke-Command remoting"},
    {"powershell.exe","new-pssession", "PowerShell New-PSSession (WinRM)"},
    {"powershell.exe","enter-pssession","PowerShell Enter-PSSession (WinRM)"},
    {"pwsh.exe",      "invoke-command","pwsh Invoke-Command remoting"},
    // schtasks remote
    {"schtasks.exe",  "/s ",          "schtasks remote scheduled task creation"},
    // net use / at.exe
    {"net.exe",       "use \\\\",     "net use mounting remote share (lateral movement)"},
    {"at.exe",        "\\\\",         "at.exe remote job scheduling (legacy lateral movement)"},
    // Impacket-style tools (python-based, surface through image name)
    {"wmiexec.py",    "",             "Impacket wmiexec execution"},
    {"smbexec.py",    "",             "Impacket smbexec execution"},
    {"atexec.py",     "",             "Impacket atexec execution"},
    {"dcomexec.py",   "",             "Impacket dcomexec execution"},
    // CrackMapExec / evil-winrm artifacts
    {"crackmapexec.exe","",           "CrackMapExec lateral movement tool"},
    {"evil-winrm.exe", "",            "evil-winrm remote shell tool"},
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
        det.severity          = avcore::Severity::Malicious;
        det.target_path       = event.image_path;
        det.process_id        = event.process_id;
        det.parent_process_id = event.parent_process_id;
        det.evidence          = std::string(pat.description) + ". Command line: " + event.command_line;
        return det;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
