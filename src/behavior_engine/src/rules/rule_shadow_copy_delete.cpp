#include "rules/rule_shadow_copy_delete.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

using avcore::Severity;

struct ShadowPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
    Severity    severity;
};

// Backup/shadow destruction is Malicious (ransomware precursor). Read-only
// enumeration and generic manipulation are Suspicious recon. NOTE: a bare
// ".delete()" pattern was removed -- it matched any .NET method call
// ($file.Delete(), $regkey.Delete(), ...) and produced Malicious false
// positives unrelated to shadow copies.
constexpr ShadowPattern kPatterns[] = {
    // vssadmin -- destruction
    {"vssadmin.exe", "delete shadows",          "vssadmin deleting all shadow copies (ransomware)", Severity::Malicious},
    {"vssadmin.exe", "resize shadowstorage",    "vssadmin resizing shadow storage to minimum (ransomware)", Severity::Malicious},
    // wmic -- destruction
    {"wmic.exe",     "shadowcopy delete",       "wmic deleting shadow copies (ransomware)", Severity::Malicious},
    {"wmic.exe",     "shadowcopy where",        "wmic deleting specific shadow copies (ransomware)", Severity::Malicious},
    // bcdedit -- recovery disable is Malicious; safeboot config is dual-use
    {"bcdedit.exe",  "recoveryenabled no",      "bcdedit disabling Windows recovery (ransomware)", Severity::Malicious},
    {"bcdedit.exe",  "/set {default} no",       "bcdedit disabling boot recovery options", Severity::Malicious},
    {"bcdedit.exe",  "safeboot",                "bcdedit modifying safeboot configuration", Severity::Suspicious},
    // wbadmin (Windows Backup) -- destruction
    {"wbadmin.exe",  "delete catalog",          "wbadmin deleting backup catalog (ransomware)", Severity::Malicious},
    {"wbadmin.exe",  "delete systemstatebackup","wbadmin deleting system state backup (ransomware)", Severity::Malicious},
    // PowerShell -- enumeration/manipulation is recon (Suspicious)
    {"powershell.exe", "get-wmiobject win32_shadowcopy", "PowerShell enumerating shadow copies (recon)", Severity::Suspicious},
    {"pwsh.exe",     "shadowcopy",              "pwsh shadow copy manipulation", Severity::Suspicious},
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
