#include "rules/rule_persistence_registry.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct RegPersistPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr RegPersistPattern kPatterns[] = {
    // reg.exe writing Run/RunOnce
    {"reg.exe", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
     "reg.exe writing HKCU Run key (user persistence)"},
    {"reg.exe", "hklm\\software\\microsoft\\windows\\currentversion\\run",
     "reg.exe writing HKLM Run key (system-wide persistence)"},
    {"reg.exe", "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
     "reg.exe writing HKCU RunOnce key (persistence)"},
    {"reg.exe", "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
     "reg.exe writing HKLM RunOnce key (persistence)"},
    // reg.exe Winlogon Userinit/Shell hijack
    {"reg.exe", "winlogon",
     "reg.exe modifying Winlogon (shell/userinit hijack)"},
    // reg.exe AppInit_DLLs
    {"reg.exe", "appinit_dlls",
     "reg.exe writing AppInit_DLLs (DLL injection persistence)"},
    // reg.exe Image File Execution Options (debugger hijack)
    {"reg.exe", "image file execution options",
     "reg.exe writing IFEO Debugger key (execution hijack)"},
    // PowerShell registry persistence
    {"powershell.exe", "currentversion\\run",
     "PowerShell writing Run key (persistence)"},
    {"powershell.exe", "appinit_dlls",
     "PowerShell writing AppInit_DLLs (DLL injection persistence)"},
    {"powershell.exe", "image file execution options",
     "PowerShell writing IFEO Debugger key (execution hijack)"},
    {"pwsh.exe", "currentversion\\run",
     "pwsh writing Run key (persistence)"},
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
