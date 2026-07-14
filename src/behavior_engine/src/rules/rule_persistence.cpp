#include "rule_persistence.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> PersistenceRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
