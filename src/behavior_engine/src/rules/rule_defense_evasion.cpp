#include "rules/rule_defense_evasion.hpp"

#include <string>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

using avcore::Severity;

struct EvasionPattern {
    const char* binary;
    const char* arg_substring;  // non-empty; bare execution never triggers here
    const char* description;
    Severity    severity;       // Malicious = clear tampering; Suspicious = dual-use
};

// Severity tiering keeps benign admin/installer activity out of the Malicious
// bucket. Actions that directly disable security controls or destroy logs stay
// Malicious; permission/attribute/firewall-exception tweaks that legitimate
// installers and admin scripts also perform are Suspicious.
constexpr EvasionPattern kPatterns[] = {
    // Event log clearing (T1070.001) -- destructive, rarely legitimate
    {"wevtutil.exe", "cl ",       "wevtutil clearing Windows event log (T1070.001)", Severity::Malicious},
    {"wevtutil.exe", "clear-log", "wevtutil clearing Windows event log",             Severity::Malicious},
    {"wevtutil.exe", "sl ",       "wevtutil setting log size to 0 (log truncation)", Severity::Malicious},
    {"powershell.exe", "clear-eventlog", "PowerShell Clear-EventLog (defense evasion)", Severity::Malicious},
    {"powershell.exe", "limit-eventlog", "PowerShell Limit-EventLog to 0 (truncation)", Severity::Malicious},
    // Firewall: disabling is Malicious; adding an exception is dual-use
    {"netsh.exe", "firewall set opmode disable",             "netsh disabling Windows Firewall (T1562.004)", Severity::Malicious},
    {"netsh.exe", "advfirewall set allprofiles state off",   "netsh disabling Windows Firewall (T1562.004)", Severity::Malicious},
    {"netsh.exe", "firewall add allowedprogram",             "netsh adding firewall exception (installers do this too)", Severity::Suspicious},
    // Defender tampering (T1562.001) -- Malicious
    {"powershell.exe", "set-mppreference -disablerealtimemonitoring",  "PowerShell disabling Defender real-time (T1562.001)", Severity::Malicious},
    {"powershell.exe", "add-mppreference -exclusionpath",              "PowerShell adding Defender exclusion (T1562.001)",   Severity::Malicious},
    {"powershell.exe", "set-mppreference -disablebehaviormonitoring",  "PowerShell disabling Defender behavior monitoring",  Severity::Malicious},
    // Permission stripping -- dual-use (admin scripts do this)
    {"icacls.exe", "/grant everyone", "icacls granting Everyone permission (permission weakening)", Severity::Suspicious},
    {"icacls.exe", "/remove",         "icacls removing ACLs (permission weakening)",                Severity::Suspicious},
    {"cacls.exe",  "/e /p everyone",  "cacls granting Everyone permission (permission weakening)",  Severity::Suspicious},
    // attrib hiding / read-only removal -- dual-use
    {"attrib.exe", "+s +h", "attrib hiding files with system+hidden attributes", Severity::Suspicious},
    {"attrib.exe", "-r",    "attrib removing read-only attribute",               Severity::Suspicious},
    // Timestomping via PowerShell (T1070.006) -- Malicious
    {"powershell.exe", "[system.io.file]::setlastwritetime",  "PowerShell timestomping LastWriteTime (T1070.006)",  Severity::Malicious},
    {"powershell.exe", "[system.io.file]::setcreationtime",   "PowerShell timestomping CreationTime (T1070.006)",   Severity::Malicious},
    {"powershell.exe", "[system.io.file]::setlastaccesstime", "PowerShell timestomping LastAccessTime (T1070.006)", Severity::Malicious},
};

// Shells / script hosts that indicate fodhelper was spawned programmatically
// (the UAC-bypass pattern) rather than by the user opening Settings.
bool IsShellOrScriptHost(const std::string& image_name_lower) {
    return image_name_lower == "cmd.exe"        || image_name_lower == "powershell.exe" ||
           image_name_lower == "pwsh.exe"       || image_name_lower == "wscript.exe"    ||
           image_name_lower == "cscript.exe"    || image_name_lower == "mshta.exe"      ||
           image_name_lower == "wmic.exe"       || image_name_lower == "rundll32.exe"   ||
           image_name_lower == "regsvr32.exe";
}

} // namespace

std::optional<avcore::DetectionEvent> RuleDefenseEvasion::Evaluate(
    const ProcessEvent& event, const ProcessTree& tree) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));

    // fodhelper.exe (T1548.002) is a legitimate Windows binary launched whenever
    // the user opens "Manage optional features". The UAC-bypass abuse is defined
    // by *who spawns it*: a shell or script host, not explorer/SystemSettings.
    // Flagging bare execution (as the old rule did) false-positived on every
    // normal Settings visit, so we require the suspicious parent context.
    if (image_name == "fodhelper.exe") {
        if (auto parent = tree.GetParent(event.process_id)) {
            const std::string parent_name =
                avcore::ToLowerAscii(avcore::Basename(parent->event.image_path));
            if (IsShellOrScriptHost(parent_name)) {
                avcore::DetectionEvent det;
                det.rule_id           = Id();
                det.source            = "behavior_engine";
                det.severity          = avcore::Severity::Malicious;
                det.target_path       = event.image_path;
                det.process_id        = event.process_id;
                det.parent_process_id = event.parent_process_id;
                det.evidence          = "fodhelper.exe spawned by " + parent_name +
                                        " (UAC bypass vector T1548.002). Command line: " +
                                        event.command_line;
                return det;
            }
        }
        return std::nullopt; // launched normally -- not suspicious
    }

    const std::string cmd_lower = avcore::ToLowerAscii(event.command_line);
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
