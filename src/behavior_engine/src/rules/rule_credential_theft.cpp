#include "rule_credential_theft.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> CredentialTheftRule::Evaluate(const ProcessEvent& event,
                                                          const ProcessTree& tree) const {
    return std::nullopt;
}

}  // namespace avbehavior
