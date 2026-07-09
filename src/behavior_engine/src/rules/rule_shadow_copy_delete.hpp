#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects ransomware-preparation: shadow copy deletion, BCDEdit recovery
// disable, and shadow storage resize -- all classic anti-recovery techniques.
class RuleShadowCopyDelete : public IRule {
public:
    std::string Id() const override { return "BEH.SHADOW_COPY_DELETE"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
