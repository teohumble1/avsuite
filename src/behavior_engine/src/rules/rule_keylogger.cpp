#include "rules/rule_keylogger.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Keystroke-capture indicators. These API/tool tokens are essentially never
// present in benign command lines, so they are high-confidence.
constexpr CommandPattern kPatterns[] = {
    {"powershell.exe", "getasynckeystate", "PowerShell polling keystrokes via GetAsyncKeyState (keylogger, T1056.001)", Severity::Malicious},
    {"pwsh.exe",       "getasynckeystate", "PowerShell polling keystrokes via GetAsyncKeyState (keylogger, T1056.001)", Severity::Malicious},
    {"powershell.exe", "setwindowshookex", "PowerShell installing a global keyboard hook (keylogger, T1056.001)", Severity::Malicious},
    {"pwsh.exe",       "setwindowshookex", "PowerShell installing a global keyboard hook (keylogger, T1056.001)", Severity::Malicious},
    {"powershell.exe", "getkeyboardstate", "PowerShell reading keyboard state (keylogger, T1056.001)", Severity::Suspicious},
    {"pwsh.exe",       "getkeyboardstate", "PowerShell reading keyboard state (keylogger, T1056.001)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> KeyloggerRule::Evaluate(const ProcessEvent& event,
                                                              const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
