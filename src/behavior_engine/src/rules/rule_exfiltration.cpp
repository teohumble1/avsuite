#include "rules/rule_exfiltration.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Data-exfiltration indicators (T1041/T1567). Uploading data and cloud-copy
// tooling are genuinely dual-use (backups, CI artifact upload), so these are
// Suspicious rather than Malicious. Download cradles are intentionally NOT here
// -- those belong to the PowerShell-obfuscation rule.
constexpr CommandPattern kPatterns[] = {
    {"curl.exe",       "--upload-file",  "curl uploading a file (possible data exfiltration, T1041)", Severity::Suspicious},
    {"curl.exe",       "-t ",            "curl -T uploading a file (possible data exfiltration, T1041)", Severity::Suspicious},
    {"powershell.exe", "uploadfile(",    "PowerShell WebClient.UploadFile (data exfiltration, T1041)", Severity::Suspicious},
    {"powershell.exe", "uploadstring(",  "PowerShell WebClient.UploadString (data exfiltration, T1041)", Severity::Suspicious},
    {"powershell.exe", "-method post",   "PowerShell HTTP POST (possible data exfiltration, T1041)", Severity::Suspicious},
    {"pwsh.exe",       "-method post",   "PowerShell HTTP POST (possible data exfiltration, T1041)", Severity::Suspicious},
    {"bitsadmin.exe",  "/upload",        "bitsadmin uploading via BITS (possible exfiltration, T1048)", Severity::Suspicious},
    {"rclone.exe",     "",               "rclone cloud-copy tool launched (possible exfiltration to cloud storage, T1567.002)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> ExfiltrationRule::Evaluate(const ProcessEvent& event,
                                                                 const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
