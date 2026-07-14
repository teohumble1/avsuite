#include "rule_exfiltration.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> ExfiltrationRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
