#include "rules/rule_temp_appdata_spawn.hpp"

#include <array>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

std::optional<avcore::DetectionEvent> RuleTempAppDataSpawn::Evaluate(const ProcessEvent& event,
                                                                       const ProcessTree& tree) const {
    if (!avcore::IsUnderUserWritableDir(event.image_path)) {
        return std::nullopt;
    }

    static const std::array<const char*, 4> kAllowlistedParents = {
        "msiexec.exe", "tiworker.exe", "googleupdate.exe", "microsoftedgeupdate.exe",
    };

    const auto parent = tree.GetParent(event.process_id);
    if (parent) {
        const std::string parent_name = avcore::ToLowerAscii(avcore::Basename(parent->event.image_path));
        for (const char* allowed : kAllowlistedParents) {
            if (parent_name == allowed) return std::nullopt;
        }
    }

    avcore::DetectionEvent detection;
    detection.rule_id = Id();
    detection.source = "behavior_engine";
    detection.severity = avcore::Severity::Suspicious;
    detection.target_path = event.image_path;
    detection.process_id = event.process_id;
    detection.parent_process_id = event.parent_process_id;
    detection.evidence = "Process image launched from a user-writable drop location ("
                          + event.image_path + ") without an allowlisted installer/updater parent.";
    return detection;
}

} // namespace avbehavior::rules
