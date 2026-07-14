#include "rule_injection.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> InjectionRule::Evaluate(const ProcessEvent& event,
                                                               const ProcessTree& tree) const {
    // TODO: Unsigned from TEMP + WriteProcessMemory + CreateRemoteThread pattern
    return std::nullopt;
}

}  // namespace avbehavior
