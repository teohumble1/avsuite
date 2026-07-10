#include "rules/rule_credential_access.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct CredPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr CredPattern kPatterns[] = {
    // Procdump targeting lsass.exe
    {"procdump.exe",  "lsass",         "procdump targeting lsass.exe (credential dump)"},
    {"procdump64.exe","lsass",         "procdump64 targeting lsass.exe (credential dump)"},
    // rundll32 comsvcs.dll MiniDump (Lolbin dump)
    {"rundll32.exe",  "comsvcs",       "rundll32 comsvcs.dll MiniDump (lsass credential dump)"},
    {"rundll32.exe",  "minidump",      "rundll32 MiniDump call (credential dump)"},
    // reg.exe saving hives
    {"reg.exe",       "save hklm\\sam",       "reg.exe saving SAM hive (credential dump)"},
    {"reg.exe",       "save hklm\\system",    "reg.exe saving SYSTEM hive (credential dump)"},
    {"reg.exe",       "save hklm\\security",  "reg.exe saving SECURITY hive (credential dump)"},
    // PowerShell credential dump helpers. NOTE: a bare "lsass" substring is
    // deliberately NOT used here -- legitimate admin one-liners like
    // "Get-Process lsass" reference lsass without dumping it. Only specific
    // dump techniques are matched.
    {"powershell.exe","sekurlsa",      "PowerShell with Mimikatz sekurlsa (credential dump)"},
    {"powershell.exe","invoke-mimikatz","PowerShell Invoke-Mimikatz (credential dump)"},
    {"powershell.exe","out-minidump",  "PowerShell Out-Minidump (process memory dump)"},
    {"powershell.exe","dcsync",        "PowerShell DCSync attack (credential dump)"},
    // ntdsutil for NTDS.dit copy
    {"ntdsutil.exe",  "ac i ntds",     "ntdsutil accessing NTDS.dit (AD credential dump)"},
    {"ntdsutil.exe",  "ifm",           "ntdsutil IFM media creation (NTDS.dit copy)"},
    // wce, pwdump
    {"wce.exe",       "",              "Windows Credential Editor execution (credential dump)"},
    {"pwdump.exe",    "",              "pwdump execution (credential dump)"},
    {"pwdump7.exe",   "",              "pwdump7 execution (credential dump)"},
    {"fgdump.exe",    "",              "fgdump execution (credential dump)"},
    // LaZagne
    {"lazagne.exe",   "",              "LaZagne credential recovery tool execution"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleCredentialAccess::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string cmd_lower  = avcore::ToLowerAscii(event.command_line);

    for (const auto& pat : kPatterns) {
        if (image_name != pat.binary) continue;
        // Empty arg_substring means binary match alone is sufficient
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
