#include "rule_rootkit.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> RootkitRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
