#include "rules/rule_ransomware_indicator.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct RansomPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr RansomPattern kPatterns[] = {
    // cipher /w: overwrite free space (anti-forensics / ransomware)
    {"cipher.exe",   "/w:",                 "cipher.exe /w overwriting free space (ransomware anti-recovery)"},
    {"cipher.exe",   " /w ",                "cipher.exe /w overwriting free space (ransomware anti-recovery)"},
    // format.com (disk wipe)
    {"format.com",   "",                    "format.com execution (disk wipe indicator)"},
    // PowerShell mass file rename / encrypt loop indicators
    {"powershell.exe","rename-item",        "PowerShell Rename-Item (possible mass rename for ransom)"},
    {"powershell.exe","[system.io.file]::move","PowerShell File.Move loop (ransomware file movement)"},
    // Known ransomware process names
    {"lockbit.exe",  "",                    "LockBit ransomware executable detected"},
    {"ryuk.exe",     "",                    "Ryuk ransomware executable detected"},
    {"conti.exe",    "",                    "Conti ransomware executable detected"},
    {"revil.exe",    "",                    "REvil ransomware executable detected"},
    {"blackcat.exe", "",                    "BlackCat/ALPHV ransomware executable detected"},
    {"blackmatter.exe","",                  "BlackMatter ransomware executable detected"},
    {"clop.exe",     "",                    "Clop ransomware executable detected"},
    // fsutil behavior disable
    {"fsutil.exe",   "usn deletejournal",   "fsutil deleting USN journal (anti-forensics)"},
    {"fsutil.exe",   "behavior set disablelastaccess", "fsutil disabling last access timestamps"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleRansomwareIndicator::Evaluate(
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
