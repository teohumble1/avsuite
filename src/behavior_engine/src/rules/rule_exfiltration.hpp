#pragma once
#include "avbehavior/rule_base.hpp"

namespace avbehavior {

class ExfiltrationRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.EXFILTRATION"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

