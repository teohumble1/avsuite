#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Detect commands that target security product services/processes:
//   sc.exe stop/delete WinDefend
//   net.exe stop "Windows Defender"
//   taskkill /im MsMpEng.exe
//   ...etc.
//
// These are textbook AV-killer patterns used by ransomware and AV-terminator
// tools (including Rust-based ones like vukhi_diet_av.exe).
class RuleAvKillerChild : public IRule {
public:
    std::string Id() const override { return "BEH.AV_KILLER_COMMAND"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
