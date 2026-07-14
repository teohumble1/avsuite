#include "rules/rule_persistence.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Non-registry persistence complementing RulePersistenceRegistry (Run keys,
// Winlogon, AppInit, IFEO). Here: scheduled tasks, service creation, Startup
// folder drops (all dual-use -> Suspicious) and WMI event-subscription
// persistence (rarely legitimate -> Malicious). MITRE T1053/T1543/T1547/T1546.
constexpr CommandPattern kPatterns[] = {
    {"schtasks.exe",   "/create",          "schtasks creating a scheduled task (persistence, T1053.005)", Severity::Suspicious},
    {"sc.exe",         "create",           "sc.exe creating a service (persistence, T1543.003)", Severity::Suspicious},
    {"powershell.exe", "new-scheduledtask","PowerShell registering a scheduled task (persistence, T1053.005)", Severity::Suspicious},
    {"pwsh.exe",       "new-scheduledtask","PowerShell registering a scheduled task (persistence, T1053.005)", Severity::Suspicious},
    {"",               "\\startup\\",      "Writing to the Startup folder (persistence, T1547.001)", Severity::Suspicious},
    // WMI permanent event subscription -- a rarely-legitimate stealth persistence.
    {"powershell.exe", "__eventfilter",              "PowerShell creating a WMI event filter (persistence, T1546.003)", Severity::Malicious},
    {"powershell.exe", "commandlineeventconsumer",   "PowerShell creating a WMI CommandLineEventConsumer (persistence, T1546.003)", Severity::Malicious},
    {"wmic.exe",       "__eventfilter",              "WMIC creating a WMI event filter (persistence, T1546.003)", Severity::Malicious},
};

} // namespace

std::optional<avcore::DetectionEvent> PersistenceRule::Evaluate(const ProcessEvent& event,
                                                                const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
