#include "rules/rule_wmi_execution.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct WmiPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

// Only WMI *execution* and *persistence* patterns belong here. Read-only WMI
// queries (Get-WmiObject / Get-CimInstance / a bare "wmi" substring) are
// standard administrative and inventory activity, so the previous patterns that
// matched them produced constant Suspicious false positives and were removed.
constexpr WmiPattern kPatterns[] = {
    // wmic process call create (execution)
    {"wmic.exe", "process call create",        "wmic spawning a process via WMI (T1047)"},
    // wmic event subscription persistence
    {"wmic.exe", "eventsub",                   "wmic WMI event subscription (persistence T1546.003)"},
    {"wmic.exe", "eventfilter",                "wmic WMI event filter creation (persistence)"},
    {"wmic.exe", "commandlineeventconsumer",   "wmic CommandLineEventConsumer creation (persistence)"},
    {"wmic.exe", "activescripteventconsumer",  "wmic ActiveScriptEventConsumer creation (persistence)"},
    // wmic /format XSL scriptlet execution -- only the remote/.xsl abuse form,
    // not benign built-in formats like /format:list.
    {"wmic.exe", "/format:http",               "wmic remote XSL execution (T1220 XSL Script Processing)"},
    {"wmic.exe", ".xsl",                       "wmic XSL script processing (T1220)"},
    // wmiprvse spawning unusual children (detected by parent check)
    {"cmd.exe",         "wmiprvse",             "cmd.exe spawned by wmiprvse.exe (WMI lateral movement)"},
    // PowerShell WMI *method invocation* (execution), not read queries
    {"powershell.exe",  "invoke-wmimethod",     "PowerShell Invoke-WmiMethod (WMI execution)"},
    {"powershell.exe",  "[wmiclass]",           "PowerShell WmiClass instantiation (WMI execution)"},
    {"pwsh.exe",        "invoke-wmimethod",     "pwsh Invoke-WmiMethod (WMI execution)"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleWmiExecution::Evaluate(
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
