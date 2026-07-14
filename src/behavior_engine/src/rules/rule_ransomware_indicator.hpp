#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects ransomware behavioral indicators beyond shadow copy deletion:
// cipher /w (wipe free space), forced disk encryption prep, large-scale
// rename loops (detected via process tree burst heuristic), and common
// ransomware child processes.
class RuleRansomwareIndicator : public IRule {
public:
    std::string Id() const override { return "BEH.RANSOMWARE_INDICATOR"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

