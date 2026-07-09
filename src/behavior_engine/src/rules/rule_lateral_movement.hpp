#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects lateral movement tooling: PsExec, wmic /node:, winrs.exe, at.exe,
// schtasks /s (remote), and similar remote-execution primitives.
class RuleLateralMovement : public IRule {
public:
    std::string Id() const override { return "BEH.LATERAL_MOVEMENT"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
