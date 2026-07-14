#pragma once

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

// BEH.RANSOMWARE: Detects file encryption/mass destruction patterns
// MITRE: T1486 (Data Encrypted for Impact), T1561 (Disk Wipe)
class RansomwareRule : public RuleBase {
public:
    std::string Id() const override { return "BEH.RANSOMWARE"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

}  // namespace avbehavior

