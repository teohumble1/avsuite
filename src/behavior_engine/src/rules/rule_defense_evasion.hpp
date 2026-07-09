#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects defense evasion: icacls/cacls permission stripping on system dirs,
// timestomping via PowerShell/touch, event log clearing (wevtutil cl),
// firewall rule deletion/disable, and UAC bypass patterns.
class RuleDefenseEvasion : public IRule {
public:
    std::string Id() const override { return "BEH.DEFENSE_EVASION"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
