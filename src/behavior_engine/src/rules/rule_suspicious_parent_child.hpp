#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Classic macro-malware indicator: an Office application spawning a
// scripting/command interpreter. Cheap to check, low false-positive rate.
class RuleSuspiciousParentChild : public IRule {
public:
    std::string Id() const override { return "BEH.OFFICE_SPAWNS_SHELL"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

