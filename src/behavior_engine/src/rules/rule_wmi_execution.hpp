#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects WMI-based execution and persistence: wmic process call create,
// event subscription creation, WMI namespace queries for lateral movement.
class RuleWmiExecution : public IRule {
public:
    std::string Id() const override { return "BEH.WMI_EXECUTION"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

