#include "rules/rule_ransomware.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Ransomware coverage complementing RuleRansomwareIndicator / RuleRansomwareFileOps
// (which handle vssadmin/wmic shadow deletion, bcdedit recoveryenabled, cipher/w,
// and family binaries). Here we add further recovery-tampering variants and a
// broader set of ransomware family binaries (T1490 inhibit recovery, T1486). All
// are rarely-legitimate and flagged Malicious.
constexpr CommandPattern kPatterns[] = {
    {"vssadmin.exe", "resize shadowstorage",       "vssadmin shrinking shadow storage to purge backups (T1490)", Severity::Malicious},
    {"wbadmin.exe",  "delete systemstatebackup",   "wbadmin deleting system-state backup (T1490)", Severity::Malicious},
    {"bcdedit.exe",  "bootstatuspolicy ignoreallfailures", "bcdedit suppressing the recovery UI (ransomware anti-recovery, T1490)", Severity::Malicious},
    {"schtasks.exe", "/change /tn \"\\microsoft\\windows\\systemrestore", "schtasks disabling System Restore task (T1490)", Severity::Malicious},
    // Additional ransomware family binaries not in RuleRansomwareIndicator.
    {"wannacry.exe",   "", "WannaCry ransomware executable detected", Severity::Malicious},
    {"petya.exe",      "", "Petya/NotPetya ransomware executable detected", Severity::Malicious},
    {"maze.exe",       "", "Maze ransomware executable detected", Severity::Malicious},
    {"sodinokibi.exe", "", "Sodinokibi/REvil ransomware executable detected", Severity::Malicious},
    {"darkside.exe",   "", "DarkSide ransomware executable detected", Severity::Malicious},
    {"akira.exe",      "", "Akira ransomware executable detected", Severity::Malicious},
    {"hive.exe",       "", "Hive ransomware executable detected", Severity::Malicious},
};

} // namespace

std::optional<avcore::DetectionEvent> RansomwareRule::Evaluate(const ProcessEvent& event,
                                                               const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
