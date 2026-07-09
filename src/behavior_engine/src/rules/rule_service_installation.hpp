#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects service-based persistence: sc.exe create, New-Service via PowerShell,
// and reg.exe writes to HKLM\SYSTEM\CurrentControlSet\Services.
class RuleServiceInstallation : public IRule {
public:
    std::string Id() const override { return "BEH.SERVICE_INSTALL"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
