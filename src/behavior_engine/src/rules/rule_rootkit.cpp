#include "rules/rule_rootkit.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Kernel-driver loading and bring-your-own-vulnerable-driver (BYOVD) indicators
// (T1014 rootkit, T1068 exploitation for privilege escalation). Loading a kernel
// service or a known-vulnerable driver is the enabling step for rootkits; the
// named vulnerable drivers are rarely-legitimate and flagged Malicious, while
// generic kernel-service creation is Suspicious (some legitimate drivers install
// this way).
// Ordered most-specific first: a known bring-your-own-vulnerable-driver name is
// higher-severity and must win over the generic kernel-service-creation match,
// since a `sc create ... type= kernel` command can contain both.
constexpr CommandPattern kPatterns[] = {
    // Known BYOVD drivers abused to gain kernel execution -- Malicious.
    {"",             "rtcore64.sys",  "Loading RTCore64.sys (known BYOVD, T1068)", Severity::Malicious},
    {"",             "dbutil_2_3.sys","Loading dbutil_2_3.sys (known BYOVD, T1068)", Severity::Malicious},
    {"",             "gdrv.sys",      "Loading gdrv.sys (known BYOVD, T1068)", Severity::Malicious},
    {"",             "winring0x64.sys","Loading WinRing0x64.sys (known BYOVD, T1068)", Severity::Malicious},
    {"",             "procexp152.sys","Loading procexp152.sys (abused Process Explorer driver, T1068)", Severity::Malicious},
    // Generic kernel-driver loading -- dual-use, Suspicious.
    {"sc.exe",       "type= kernel",  "sc.exe creating a kernel-mode driver service (possible rootkit/BYOVD, T1014)", Severity::Suspicious},
    {"sc.exe",       "type=kernel",   "sc.exe creating a kernel-mode driver service (possible rootkit/BYOVD, T1014)", Severity::Suspicious},
    {"fltmc.exe",    "load",          "fltmc loading a filesystem filter driver (possible rootkit, T1014)", Severity::Suspicious},
    {"drvload.exe",  "",              "drvload loading a driver (possible rootkit, T1014)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> RootkitRule::Evaluate(const ProcessEvent& event,
                                                            const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
