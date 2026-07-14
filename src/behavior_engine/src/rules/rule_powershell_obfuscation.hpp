#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects PowerShell invoked with obfuscation, download cradles, AMSI bypass,
// encoded commands, or other indicators of malicious in-memory execution.
class RulePowerShellObfuscation : public IRule {
public:
    std::string Id() const override { return "BEH.PS_OBFUSCATION"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

