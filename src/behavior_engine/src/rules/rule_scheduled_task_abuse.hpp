#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects scheduled task creation used for persistence or execution:
// schtasks.exe /create, at.exe, and PowerShell New-ScheduledTask/Register-ScheduledTask.
class RuleScheduledTaskAbuse : public IRule {
public:
    std::string Id() const override { return "BEH.SCHTASK_ABUSE"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
