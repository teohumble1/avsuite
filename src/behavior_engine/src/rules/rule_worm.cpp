#include "rules/rule_worm.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Self-propagation indicators (T1091 removable media, T1021.002 admin shares).
// Copying to an administrative share or dropping an autorun.inf is worm-like;
// copying to an ordinary UNC file share is a normal backup, so only admin$
// targets are flagged here.
constexpr CommandPattern kPatterns[] = {
    {"xcopy.exe",    "\\admin$",   "xcopy writing to a remote ADMIN$ share (worm-style propagation, T1021.002)", Severity::Suspicious},
    {"robocopy.exe", "\\admin$",   "robocopy writing to a remote ADMIN$ share (worm-style propagation, T1021.002)", Severity::Suspicious},
    {"xcopy.exe",    "\\c$\\",     "xcopy writing to a remote C$ admin share (worm-style propagation, T1021.002)", Severity::Suspicious},
    {"",             "autorun.inf", "Writing an autorun.inf (removable-media worm propagation, T1091)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> WormRule::Evaluate(const ProcessEvent& event,
                                                         const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
