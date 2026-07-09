#include "rules/rule_scheduled_task_abuse.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct SchedPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr SchedPattern kPatterns[] = {
    // schtasks /create with suspicious locations
    {"schtasks.exe", "/create",                 "schtasks.exe creating a scheduled task (persistence T1053.005)"},
    {"schtasks.exe", "/change",                 "schtasks.exe modifying a scheduled task"},
    // at.exe (legacy, still widely abused)
    {"at.exe",       "",                        "at.exe job creation (legacy scheduled task, T1053.002)"},
    // PowerShell scheduled task creation
    {"powershell.exe","register-scheduledtask", "PowerShell Register-ScheduledTask (persistence)"},
    {"powershell.exe","new-scheduledtask",      "PowerShell New-ScheduledTask (persistence)"},
    {"powershell.exe","new-scheduledtaskaction","PowerShell New-ScheduledTaskAction (persistence)"},
    {"pwsh.exe",     "register-scheduledtask",  "pwsh Register-ScheduledTask (persistence)"},
    // xmlrpc / schtasks via xml
    {"schtasks.exe", "/xml",                    "schtasks.exe task created from XML (potential obfuscation)"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleScheduledTaskAbuse::Evaluate(
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
