#include "rule_keylogger.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> KeyloggerRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
