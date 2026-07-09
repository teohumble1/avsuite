#include "rules/rule_powershell_obfuscation.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct PsPattern {
    const char* arg_substring;
    const char* description;
};

// Patterns checked against the full command line (lowercased)
constexpr PsPattern kPatterns[] = {
    // Encoded command execution
    {"-encodedcommand",         "PowerShell EncodedCommand (base64 payload)"},
    {"-enc ",                   "PowerShell -enc shorthand (encoded command)"},
    {"-e ",                     "PowerShell -e shorthand (encoded command)"},
    // Download cradles
    {"invoke-webrequest",       "PowerShell Invoke-WebRequest download cradle"},
    {"iwr ",                    "PowerShell IWR alias download cradle"},
    {"(new-object net.webclient)", "PowerShell WebClient download cradle"},
    {"downloadstring(",         "PowerShell DownloadString in-memory execution"},
    {"downloadfile(",           "PowerShell DownloadFile drop-and-execute"},
    {"start-bitstransfer",      "PowerShell Start-BitsTransfer download cradle"},
    // Bypass flags
    {"-executionpolicy bypass", "PowerShell -ExecutionPolicy Bypass"},
    {"-ep bypass",              "PowerShell -ep bypass shorthand"},
    {"-windowstyle hidden",     "PowerShell hidden window (anti-UI)"},
    {"-noprofile",              "PowerShell -NoProfile (bypass profile scripts)"},
    {"-noninteractive",         "PowerShell -NonInteractive (headless execution)"},
    // Reflection / in-memory assembly loading
    {"[reflection.assembly]::load", "PowerShell reflection assembly load (fileless)"},
    {"[system.reflection.assembly]::load", "PowerShell reflection load (fileless)"},
    {"::loadfrom(",             "PowerShell LoadFrom (loading assembly from disk/URL)"},
    {"::loadfile(",             "PowerShell LoadFile (loading assembly from path)"},
    // AMSI bypass indicators
    {"amsi",                    "PowerShell references to AMSI (possible bypass)"},
    {"amsiutils",               "PowerShell AmsiUtils class (AMSI patch target)"},
    {"amsiscanb",               "PowerShell AmsiScanBuffer (AMSI patch target)"},
    // Invoke-Expression abuse
    {"invoke-expression",       "PowerShell Invoke-Expression (dynamic execution)"},
    {"iex(",                    "PowerShell IEX alias (dynamic execution)"},
    {"iex ",                    "PowerShell IEX alias (dynamic execution)"},
    // Obfuscation indicators
    {"`i`e`x",                  "PowerShell backtick-obfuscated IEX"},
    {"[char]",                  "PowerShell char-cast obfuscation"},
    {"-join",                   "PowerShell string-join obfuscation (char array)"},
    // Memory injection helpers
    {"virtualalloc",            "PowerShell VirtualAlloc call (shellcode injection)"},
    {"createthread",            "PowerShell CreateThread call (shellcode injection)"},
    {"writememory",             "PowerShell WriteMemory call (process injection)"},
};

bool IsPowerShell(const std::string& image_name_lower) {
    return image_name_lower == "powershell.exe" || image_name_lower == "pwsh.exe";
}

} // namespace

std::optional<avcore::DetectionEvent> RulePowerShellObfuscation::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    if (!IsPowerShell(image_name)) return std::nullopt;

    const std::string cmd_lower = avcore::ToLowerAscii(event.command_line);

    for (const auto& pat : kPatterns) {
        if (cmd_lower.find(pat.arg_substring) == std::string::npos) continue;

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
