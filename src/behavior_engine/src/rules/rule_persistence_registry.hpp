#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects persistence via registry Run/RunOnce keys: reg.exe or PowerShell
// writing HKCU/HKLM\...\CurrentVersion\Run entries.
class RulePersistenceRegistry : public IRule {
public:
    std::string Id() const override { return "BEH.PERSISTENCE_REG_RUN"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

