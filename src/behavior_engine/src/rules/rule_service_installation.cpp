#include "rules/rule_service_installation.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct SvcPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr SvcPattern kPatterns[] = {
    // sc.exe create
    {"sc.exe", "create",                        "sc.exe creating a new service (persistence T1543.003)"},
    // sc.exe config start=auto/demand
    {"sc.exe", "config",                        "sc.exe reconfiguring an existing service"},
    // reg.exe adding service key
    {"reg.exe", "currentcontrolset\\services",  "reg.exe writing to Services registry key (persistence)"},
    // PowerShell New-Service
    {"powershell.exe", "new-service",           "PowerShell New-Service (persistence T1543.003)"},
    {"powershell.exe", "set-service",           "PowerShell Set-Service reconfiguration"},
    {"pwsh.exe",       "new-service",           "pwsh New-Service (persistence)"},
    // installutil.exe (LOLBin service/assembly registration)
    {"installutil.exe","",                      "installutil.exe executing .NET assembly (T1218.004)"},
    // regsvr32 registering a DLL as a COM server (often service-like)
    {"regsvr32.exe",   "/s",                    "regsvr32 silent DLL/COM server registration"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleServiceInstallation::Evaluate(
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
        det.severity          = avcore::Severity::Suspicious;
        det.target_path       = event.image_path;
        det.process_id        = event.process_id;
        det.parent_process_id = event.parent_process_id;
        det.evidence          = std::string(pat.description) + ". Command line: " + event.command_line;
        return det;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
