#include "rules/rule_persistence_registry.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

using avcore::Severity;

struct RegPersistPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
    Severity    severity;
};

// Severity tiering: Run/RunOnce auto-start entries are written by a huge amount
// of legitimate software (updaters, cloud-sync clients, chat apps, drivers), so
// they are Suspicious rather than Malicious. The stealthier hijack locations
// (Winlogon shell/userinit, AppInit_DLLs, Image File Execution Options debugger)
// are almost never legitimate and stay Malicious.
constexpr RegPersistPattern kPatterns[] = {
    // reg.exe writing Run/RunOnce -- dual-use auto-start
    {"reg.exe", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
     "reg.exe writing HKCU Run key (auto-start)", Severity::Suspicious},
    {"reg.exe", "hklm\\software\\microsoft\\windows\\currentversion\\run",
     "reg.exe writing HKLM Run key (system-wide auto-start)", Severity::Suspicious},
    {"reg.exe", "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
     "reg.exe writing HKCU RunOnce key (auto-start)", Severity::Suspicious},
    {"reg.exe", "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
     "reg.exe writing HKLM RunOnce key (auto-start)", Severity::Suspicious},
    // reg.exe Winlogon Userinit/Shell hijack -- rarely legitimate
    {"reg.exe", "winlogon",
     "reg.exe modifying Winlogon (shell/userinit hijack)", Severity::Malicious},
    // reg.exe AppInit_DLLs
    {"reg.exe", "appinit_dlls",
     "reg.exe writing AppInit_DLLs (DLL injection persistence)", Severity::Malicious},
    // reg.exe Image File Execution Options (debugger hijack)
    {"reg.exe", "image file execution options",
     "reg.exe writing IFEO Debugger key (execution hijack)", Severity::Malicious},
    // PowerShell registry persistence
    {"powershell.exe", "currentversion\\run",
     "PowerShell writing Run key (auto-start)", Severity::Suspicious},
    {"powershell.exe", "appinit_dlls",
     "PowerShell writing AppInit_DLLs (DLL injection persistence)", Severity::Malicious},
    {"powershell.exe", "image file execution options",
     "PowerShell writing IFEO Debugger key (execution hijack)", Severity::Malicious},
    {"pwsh.exe", "currentversion\\run",
     "pwsh writing Run key (auto-start)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> RulePersistenceRegistry::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string cmd_lower  = avcore::ToLowerAscii(event.command_line);

    for (const auto& pat : kPatterns) {
        if (image_name != pat.binary) continue;
        if (cmd_lower.find(pat.arg_substring) == std::string::npos) continue;

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
