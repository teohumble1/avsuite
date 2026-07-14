#pragma once
#include "avbehavior/rule_base.hpp"

namespace avbehavior {

class PersistenceRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.PERSISTENCE"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

