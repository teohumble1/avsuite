#include "rules/rule_c2_beaconing.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Command-and-control / reverse-shell launch fingerprints (T1071/T1059). True
// beaconing needs network telemetry to confirm, but the launch of a raw TCP
// client from a script host, netcat with an -e payload, or a named C2 agent are
// strong, rarely-legitimate indicators observable at process creation.
constexpr CommandPattern kPatterns[] = {
    {"nc.exe",         "-e ",            "Netcat with -e (bind/reverse shell, C2)", Severity::Malicious},
    {"ncat.exe",       "-e ",            "Ncat with -e (bind/reverse shell, C2)", Severity::Malicious},
    {"nc64.exe",       "-e ",            "Netcat64 with -e (bind/reverse shell, C2)", Severity::Malicious},
    {"powershell.exe", "new-object system.net.sockets.tcpclient", "PowerShell raw TCP client (reverse shell / C2 beacon, T1071)", Severity::Malicious},
    {"pwsh.exe",       "new-object system.net.sockets.tcpclient", "PowerShell raw TCP client (reverse shell / C2 beacon, T1071)", Severity::Malicious},
    {"powershell.exe", "new-object net.sockets.tcpclient",        "PowerShell raw TCP client (reverse shell / C2 beacon, T1071)", Severity::Malicious},
    {"beacon.exe",     "",               "Cobalt Strike beacon artifact executed", Severity::Malicious},
    {"chisel.exe",     "",               "chisel tunnelling tool launched (possible C2 tunnel, T1572)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> C2BeaconingRule::Evaluate(const ProcessEvent& event,
                                                                const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
