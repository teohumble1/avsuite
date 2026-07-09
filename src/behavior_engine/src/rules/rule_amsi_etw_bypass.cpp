#include "rules/rule_amsi_etw_bypass.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

// These patterns appear in PowerShell/C# AMSI and ETW bypass scripts.
// Checked against the full command line lowercased.
constexpr const char* kBypassPatterns[] = {
    // AMSI patch via reflection
    "amsiscanb",
    "amsiutils",
    "amsicontext",
    "amsiinitialisebuffer",
    "amsiopenssession",
    // AMSI bypass via COM
    "[ref].assembly.gettype('system.management.automation.amsiutils')",
    // ETW bypass via NtTraceEvent/EtwEventWrite patch
    "etwventwrite",
    "etweventwrite",
    "nttracecontrol",
    // Generic reflection patching
    "getdelegateforfunction",
    "virtualprotect",
    "marshal]::writebyte",
    "marshal]::copy",
    // Specific bypass strings
    "disableamsi",
    "bypassamsi",
    "setamsicontext",
    "patch-amsi",
    // CLM bypass
    "system.management.automation.utils",
    "cachedgrouppolicysettings",
};

bool IsPowerShellOrDotNet(const std::string& image_name_lower) {
    return image_name_lower == "powershell.exe"
        || image_name_lower == "pwsh.exe"
        || image_name_lower == "csc.exe"
        || image_name_lower == "msbuild.exe"
        || image_name_lower == "installutil.exe";
}

} // namespace

std::optional<avcore::DetectionEvent> RuleAmsiEtwBypass::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    if (!IsPowerShellOrDotNet(image_name)) return std::nullopt;

    const std::string cmd_lower = avcore::ToLowerAscii(event.command_line);

    for (const char* pattern : kBypassPatterns) {
        if (cmd_lower.find(pattern) == std::string::npos) continue;

        avcore::DetectionEvent det;
        det.rule_id           = Id();
        det.source            = "behavior_engine";
        det.severity          = avcore::Severity::Malicious;
        det.target_path       = event.image_path;
        det.process_id        = event.process_id;
        det.parent_process_id = event.parent_process_id;
        det.evidence          = std::string("AMSI/ETW bypass pattern '") + pattern
                                + "' detected. Command line: " + event.command_line;
        return det;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
