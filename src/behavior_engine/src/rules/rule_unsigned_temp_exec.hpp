#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Flags a process whose image runs from a user-writable drop location and
// has no valid Authenticode signature. Reuses avpe::IsAuthenticodeSigned
// rather than re-implementing WinVerifyTrust here.
class RuleUnsignedTempExec : public IRule {
public:
    std::string Id() const override { return "BEH.UNSIGNED_TEMP_EXEC"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
