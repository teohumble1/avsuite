#pragma once
#include "avbehavior/rule_base.hpp"

namespace avbehavior {

class InjectionRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.INJECTION"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

