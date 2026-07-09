#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detects credential dumping: lsass.exe targeted by procdump/comsvcs,
// SAM/SYSTEM/SECURITY registry hive saves, and NTDS.dit copies.
class RuleCredentialAccess : public IRule {
public:
    std::string Id() const override { return "BEH.CREDENTIAL_ACCESS"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
