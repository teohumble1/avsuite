#include "rules/rule_suspicious_parent_child.hpp"

#include <array>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

bool IsOfficeApp(const std::string& basename_lower) {
    static const std::array<const char*, 4> kOfficeApps = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    };
    for (const char* app : kOfficeApps) {
        if (basename_lower == app) return true;
    }
    return false;
}

bool IsShellInterpreter(const std::string& basename_lower) {
    static const std::array<const char*, 5> kInterpreters = {
        "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "rundll32.exe",
    };
    for (const char* interp : kInterpreters) {
        if (basename_lower == interp) return true;
    }
    return false;
}

} // namespace

std::optional<avcore::DetectionEvent> RuleSuspiciousParentChild::Evaluate(const ProcessEvent& event,
                                                                            const ProcessTree& tree) const {
    if (!IsShellInterpreter(avcore::ToLowerAscii(avcore::Basename(event.image_path)))) {
        return std::nullopt;
    }

    const auto parent = tree.GetParent(event.process_id);
    if (!parent) return std::nullopt;

    const std::string parent_name = avcore::ToLowerAscii(avcore::Basename(parent->event.image_path));
    if (!IsOfficeApp(parent_name)) return std::nullopt;

    avcore::DetectionEvent detection;
    detection.rule_id = Id();
    detection.source = "behavior_engine";
    detection.severity = avcore::Severity::Malicious;
    detection.target_path = event.image_path;
    detection.process_id = event.process_id;
    detection.parent_process_id = event.parent_process_id;
    detection.evidence = parent_name + " spawned " + avcore::Basename(event.image_path)
                          + " -- classic macro-malware indicator.";
    return detection;
}

} // namespace avbehavior::rules
