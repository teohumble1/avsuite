#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Flags a new process whose image lives under %TEMP%/%APPDATA%/%LOCALAPPDATA%
// /Downloads, unless its parent is a known installer/updater (msiexec,
// TiWorker, common browser updaters) -- those legitimately run code from
// those locations constantly and would otherwise drown the signal.
class RuleTempAppDataSpawn : public IRule {
public:
    std::string Id() const override { return "BEH.TEMP_APPDATA_SPAWN"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                     const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules
