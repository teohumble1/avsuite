#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Flags well-known "Living-off-the-Land Binary" abuse patterns: legitimate
// signed Windows utilities invoked with command-line arguments that are
// almost never used for benign purposes (certutil -decode, regsvr32 /i:http,
// rundll32 javascript:, mshta http...).
class RuleLolbinSuspiciousArgs : public IRule {
public:
    std::string Id() const override { return "BEH.LOLBIN_SUSP_ARGS"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
