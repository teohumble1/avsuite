#pragma once
#include "avbehavior/rule_base.hpp"

namespace avbehavior {

class C2BeaconingRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.C2_BEACONING"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

