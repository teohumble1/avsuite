#include "rules/rule_defense_evasion.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct EvasionPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr EvasionPattern kPatterns[] = {
    // Event log clearing
    {"wevtutil.exe", "cl ",             "wevtutil clearing Windows event log (defense evasion T1070.001)"},
    {"wevtutil.exe", "clear-log",       "wevtutil clearing Windows event log"},
    {"wevtutil.exe", "sl ",             "wevtutil setting log size to 0 (log truncation)"},
    {"powershell.exe","clear-eventlog", "PowerShell Clear-EventLog (defense evasion)"},
    {"powershell.exe","limit-eventlog", "PowerShell Limit-EventLog to 0 (log truncation)"},
    // Firewall manipulation
    {"netsh.exe",    "firewall set opmode disable", "netsh disabling Windows Firewall (T1562.004)"},
    {"netsh.exe",    "advfirewall set allprofiles state off", "netsh disabling Windows Firewall (T1562.004)"},
    {"netsh.exe",    "firewall add allowedprogram", "netsh adding firewall exception (possible C2 comms)"},
    // Defender real-time protection disable
    {"powershell.exe","set-mppreference -disablerealtimemonitoring", "PowerShell disabling Defender real-time (T1562.001)"},
    {"powershell.exe","add-mppreference -exclusionpath",             "PowerShell adding Defender exclusion (T1562.001)"},
    {"powershell.exe","set-mppreference -disablebehaviormonitoring", "PowerShell disabling Defender behavior monitoring"},
    // icacls / cacls permission stripping on system dirs
    {"icacls.exe",   "/grant everyone",  "icacls granting Everyone permission (permission weakening)"},
    {"icacls.exe",   "/remove",          "icacls removing ACLs (permission weakening)"},
    {"cacls.exe",    "/e /p everyone",   "cacls granting Everyone permission (permission weakening)"},
    // attrib hiding
    {"attrib.exe",   "+s +h",            "attrib.exe hiding files/dirs with system+hidden attributes"},
    {"attrib.exe",   "-r",               "attrib.exe removing read-only attribute (possible timestomp prep)"},
    // UAC bypass via fodhelper
    {"fodhelper.exe","",                 "fodhelper.exe launched (UAC bypass vector T1548.002)"},
    // Timestomping via PowerShell
    {"powershell.exe","[system.io.file]::setlastwritetime",  "PowerShell timestomping LastWriteTime (T1070.006)"},
    {"powershell.exe","[system.io.file]::setcreationtime",   "PowerShell timestomping CreationTime (T1070.006)"},
    {"powershell.exe","[system.io.file]::setlastaccesstime", "PowerShell timestomping LastAccessTime (T1070.006)"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleDefenseEvasion::Evaluate(
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
