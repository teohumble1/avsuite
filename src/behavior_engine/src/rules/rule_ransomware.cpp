#include "rule_ransomware.hpp"

namespace avbehavior {

std::optional<avcore::DetectionEvent> RansomwareRule::Evaluate(const ProcessEvent& event,
                                                                const ProcessTree& tree) const {
    // TODO: Detect parent process (OfficeApp/Script) + vssadmin/wmic + entropy spikes
    // Pattern: Parent → unsigned temp binary → shadow copy delete + registry wipes
    return std::nullopt;  // Placeholder; full implementation on next pass
}

}  // namespace avbehavior
