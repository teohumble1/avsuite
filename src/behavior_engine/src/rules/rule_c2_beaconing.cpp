#include "rule_c2_beaconing.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> C2BeaconingRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
