#include "rule_worm.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> WormRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
