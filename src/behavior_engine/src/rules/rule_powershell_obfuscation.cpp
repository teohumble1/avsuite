#include "rules/rule_powershell_obfuscation.hpp"

#include <array>
#include <string>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

// Weighted, multi-signal scoring to keep false positives low. A single weak
// indicator (e.g. -NoProfile, -ExecutionPolicy Bypass) is used constantly by
// legitimate installers, CI scripts, Chocolatey/winget wrappers and scheduled
// tasks, so on its own it must NOT trigger a detection. We only escalate when
// several distinct indicator *categories* combine, or when a high-confidence
// indicator (encoded payload, reflection load, AMSI patch, shellcode helper)
// appears.
enum Category : int {
    kExecFlags = 0,   // headless/bypass flags -- extremely common in benign automation
    kEncoded,         // base64 -EncodedCommand payload
    kDownloadCradle,  // fetch-and-run over the network
    kReflection,      // in-memory assembly loading (fileless)
    kAmsiBypass,      // AMSI patch targets
    kDynamicExec,     // Invoke-Expression / IEX
    kObfuscation,     // char-cast / join / backtick tricks
    kInjection,       // VirtualAlloc/CreateThread/WriteMemory shellcode helpers
    kCategoryCount
};

// Per-category weight = confidence that this category, on its own, indicates
// malice. Weak(1): benign automation uses it. Medium(2): unusual but seen in
// admin tooling. Strong(3): rarely legitimate.
constexpr int kCategoryWeight[kCategoryCount] = {
    /*kExecFlags*/      1,
    /*kEncoded*/        3,
    /*kDownloadCradle*/ 2,
    /*kReflection*/     3,
    /*kAmsiBypass*/     3,
    /*kDynamicExec*/    2,
    /*kObfuscation*/    1,
    /*kInjection*/      3,
};

struct PsPattern {
    const char* needle;       // lowercased substring to search for
    const char* description;  // human-readable evidence
    Category    category;
};

// Patterns checked against the lowercased command line. Note: ambiguous
// substrings that used to cause false positives were removed on purpose:
//   * bare "-e " / "-e" (matched inside quoted args and unrelated flags)
//   * bare "amsi"      (matched any path/word containing the letters "amsi")
// Only specific, high-signal tokens remain.
constexpr std::array<PsPattern, 26> kPatterns = {{
    // Headless / bypass execution flags -- weak on their own
    {"-executionpolicy bypass",       "-ExecutionPolicy Bypass",           kExecFlags},
    {"-ep bypass",                     "-ep bypass (shorthand)",            kExecFlags},
    {"-windowstyle hidden",            "hidden window (-WindowStyle Hidden)", kExecFlags},
    {"-w hidden",                      "hidden window (-w hidden)",         kExecFlags},
    {"-noprofile",                     "-NoProfile",                        kExecFlags},
    {"-nop ",                          "-nop (NoProfile shorthand)",        kExecFlags},
    {"-noninteractive",               "-NonInteractive",                   kExecFlags},
    // Encoded command execution -- strong
    {"-encodedcommand",                "-EncodedCommand (base64 payload)",  kEncoded},
    {"-enc ",                          "-enc (encoded command shorthand)",  kEncoded},
    // Download cradles -- medium
    {"invoke-webrequest",              "Invoke-WebRequest download cradle", kDownloadCradle},
    {"iwr ",                           "iwr alias download cradle",         kDownloadCradle},
    {"(new-object net.webclient)",     "Net.WebClient download cradle",     kDownloadCradle},
    {"downloadstring(",                "DownloadString in-memory execution", kDownloadCradle},
    {"downloadfile(",                  "DownloadFile drop-and-execute",     kDownloadCradle},
    {"start-bitstransfer",             "Start-BitsTransfer download cradle", kDownloadCradle},
    // Reflection / fileless assembly loading -- strong
    {"[reflection.assembly]::load",    "reflection assembly load (fileless)", kReflection},
    {"[system.reflection.assembly]::load", "reflection assembly load (fileless)", kReflection},
    {"::loadfrom(",                    "Assembly.LoadFrom (disk/URL)",      kReflection},
    {"::loadfile(",                    "Assembly.LoadFile (path)",          kReflection},
    // AMSI bypass targets -- strong
    {"amsiutils",                      "AmsiUtils class (AMSI patch target)", kAmsiBypass},
    {"amsiscanbuffer",                 "AmsiScanBuffer (AMSI patch target)", kAmsiBypass},
    // Dynamic execution -- medium
    {"invoke-expression",              "Invoke-Expression (dynamic execution)", kDynamicExec},
    {"iex(",                           "IEX (dynamic execution)",           kDynamicExec},
    {"`i`e`x",                         "backtick-obfuscated IEX",           kObfuscation},
    // Memory injection helpers -- strong
    {"virtualalloc",                   "VirtualAlloc (shellcode injection)", kInjection},
    {"createthread",                   "CreateThread (shellcode injection)", kInjection},
}};

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

    // Aggregate matches per category so repeated hits in one category (e.g. two
    // bypass flags) count once toward the score rather than inflating it.
    bool matched_category[kCategoryCount] = {false};
    std::string evidence_detail;

    for (const auto& pat : kPatterns) {
        if (cmd_lower.find(pat.needle) == std::string::npos) continue;
        if (!matched_category[pat.category]) {
            matched_category[pat.category] = true;
        }
        if (!evidence_detail.empty()) evidence_detail += "; ";
        evidence_detail += pat.description;
    }

    int score = 0;
    int distinct_categories = 0;
    bool has_strong = false;
    for (int c = 0; c < kCategoryCount; ++c) {
        if (!matched_category[c]) continue;
        score += kCategoryWeight[c];
        ++distinct_categories;
        if (kCategoryWeight[c] >= 3) has_strong = true;
    }

    // Below the noise floor: a lone weak indicator (typical benign automation)
    // does not warrant an alert.
    if (score < 3) return std::nullopt;

    // Escalate to Malicious when the evidence is overwhelming: a large combined
    // score, a strong indicator backed by at least one more distinct signal, or
    // three-plus independent indicator categories.
    const bool malicious =
        score >= 5 ||
        (has_strong && distinct_categories >= 2) ||
        distinct_categories >= 3;

    avcore::DetectionEvent det;
    det.rule_id           = Id();
    det.source            = "behavior_engine";
    det.severity          = malicious ? avcore::Severity::Malicious
                                      : avcore::Severity::Suspicious;
    det.target_path       = event.image_path;
    det.process_id        = event.process_id;
    det.parent_process_id = event.parent_process_id;
    det.evidence          = "PowerShell indicator score " + std::to_string(score) +
                            " across " + std::to_string(distinct_categories) +
                            " categories (" + evidence_detail +
                            "). Command line: " + event.command_line;
    return det;
}

} // namespace avbehavior::rules
