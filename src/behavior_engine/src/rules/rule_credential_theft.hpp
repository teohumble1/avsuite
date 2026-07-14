#pragma once
#include "avbehavior/rule_base.hpp"

namespace avbehavior {

class CredentialTheftRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.CREDENTIAL_THEFT"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

