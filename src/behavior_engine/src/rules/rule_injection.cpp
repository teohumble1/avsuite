#include "rules/rule_injection.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Process-injection tooling and scripted-injection API calls (T1055). The
// memory-injection primitives (WriteProcessMemory / CreateRemoteThread /
// NtMapViewOfSection / QueueUserAPC) appearing on a command line indicate a
// scripted injector; mavinject's /injectrunning is a signed-binary DLL-injection
// LOLBin. None of these appear in benign automation.
constexpr CommandPattern kPatterns[] = {
    {"mavinject.exe",  "/injectrunning",   "mavinject injecting a DLL into a running process (T1055.001)", Severity::Malicious},
    {"powershell.exe", "writeprocessmemory", "PowerShell WriteProcessMemory (process injection, T1055)", Severity::Malicious},
    {"pwsh.exe",       "writeprocessmemory", "PowerShell WriteProcessMemory (process injection, T1055)", Severity::Malicious},
    {"powershell.exe", "createremotethread", "PowerShell CreateRemoteThread (remote thread injection, T1055)", Severity::Malicious},
    {"pwsh.exe",       "createremotethread", "PowerShell CreateRemoteThread (remote thread injection, T1055)", Severity::Malicious},
    {"powershell.exe", "ntmapviewofsection", "PowerShell NtMapViewOfSection (section-mapping injection, T1055.011)", Severity::Malicious},
    {"powershell.exe", "queueuserapc",       "PowerShell QueueUserAPC (APC injection, T1055.004)", Severity::Malicious},
    {"powershell.exe", "virtualallocex",     "PowerShell VirtualAllocEx (remote memory allocation for injection, T1055)", Severity::Malicious},
    {"pwsh.exe",       "virtualallocex",     "PowerShell VirtualAllocEx (remote memory allocation for injection, T1055)", Severity::Malicious},
};

} // namespace

std::optional<avcore::DetectionEvent> InjectionRule::Evaluate(const ProcessEvent& event,
                                                              const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
