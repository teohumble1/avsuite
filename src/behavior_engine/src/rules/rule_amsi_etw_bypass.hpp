#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects AMSI and ETW bypass techniques commonly embedded in PowerShell/C#
// scripts: reflection-based patch of AmsiScanBuffer, EtwEventWrite NOP patch,
// and [Runtime.InteropServices.Marshal] patch patterns.
class RuleAmsiEtwBypass : public IRule {
public:
    std::string Id() const override { return "BEH.AMSI_ETW_BYPASS"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

