#pragma once

#include "avbehavior/rule.hpp"

namespace avbehavior::rules {

// Flags a newly created process that is (or is launching) a cryptocurrency
// miner. Because ProcessEvent only carries the image path + command line, this
// rule keys off the miner's own launch fingerprint -- the Stratum pool URI, the
// documented XMRig CLI flags, known miner binary names, and known mining-pool
// domains -- rather than runtime CPU/network telemetry (that live signal is
// covered separately by the Network Monitor pool-IOC match and the Sys Watch
// CPU-pegging alert). Tiered so a single hard indicator is Malicious while
// weaker single hints stay Suspicious, keeping false positives down.
class RuleCryptominer : public IRule {
public:
    std::string Id() const override { return "BEH.CRYPTOMINER"; }
    std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                    const ProcessTree& tree) const override;
};

} // namespace avbehavior::rules

