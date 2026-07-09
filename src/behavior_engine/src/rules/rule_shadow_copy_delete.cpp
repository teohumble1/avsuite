#include "rules/rule_shadow_copy_delete.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct ShadowPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr ShadowPattern kPatterns[] = {
    // vssadmin
    {"vssadmin.exe", "delete shadows",          "vssadmin deleting all shadow copies (ransomware)"},
    {"vssadmin.exe", "resize shadowstorage",    "vssadmin resizing shadow storage to minimum (ransomware)"},
    // wmic
    {"wmic.exe",     "shadowcopy delete",       "wmic deleting shadow copies (ransomware)"},
    {"wmic.exe",     "shadowcopy where",        "wmic deleting specific shadow copies (ransomware)"},
    // bcdedit recovery disable
    {"bcdedit.exe",  "recoveryenabled no",      "bcdedit disabling Windows recovery (ransomware)"},
    {"bcdedit.exe",  "safeboot",                "bcdedit modifying safeboot configuration"},
    {"bcdedit.exe",  "/set {default} no",       "bcdedit disabling boot recovery options"},
    // wbadmin (Windows Backup)
    {"wbadmin.exe",  "delete catalog",          "wbadmin deleting backup catalog (ransomware)"},
    {"wbadmin.exe",  "delete systemstatebackup","wbadmin deleting system state backup (ransomware)"},
    // PowerShell equivalent
    {"powershell.exe", "get-wmiobject win32_shadowcopy", "PowerShell enumerating shadow copies (pre-delete)"},
    {"powershell.exe", ".delete()",             "PowerShell calling .Delete() on shadow copy object"},
    {"pwsh.exe",     "shadowcopy",              "pwsh shadow copy manipulation"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleShadowCopyDelete::Evaluate(
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
