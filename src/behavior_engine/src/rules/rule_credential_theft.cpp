#include "rules/rule_credential_theft.hpp"

#include "avbehavior/rule_base.hpp"

namespace avbehavior {

namespace {
using avcore::Severity;

// Credential-theft coverage that complements RuleCredentialAccess (which handles
// LSASS dumping and SAM/SYSTEM hive saves). Here we add Kerberos-abuse and
// Impacket tooling, the Windows Credential Vault, and browser credential-store
// access (T1003/T1555/T1558). Substrings are specific enough not to fire on
// benign automation.
constexpr CommandPattern kPatterns[] = {
    {"rubeus.exe",     "",              "Rubeus Kerberos ticket abuse (credential theft, T1558)", Severity::Malicious},
    {"secretsdump.py", "",              "Impacket secretsdump (remote credential extraction, T1003.006)", Severity::Malicious},
    {"kerbrute.exe",   "",              "Kerbrute Kerberos user/password enumeration (T1110)", Severity::Malicious},
    {"vaultcmd.exe",   "/listcreds",    "VaultCmd enumerating stored credentials (Credential Vault, T1555.004)", Severity::Suspicious},
    {"powershell.exe", "\\google\\chrome\\user data\\", "PowerShell accessing the Chrome credential store (browser cred theft, T1555.003)", Severity::Suspicious},
    {"powershell.exe", "\\microsoft\\edge\\user data\\", "PowerShell accessing the Edge credential store (browser cred theft, T1555.003)", Severity::Suspicious},
    {"powershell.exe", "logins.json",   "PowerShell accessing a Firefox logins store (browser cred theft, T1555.003)", Severity::Suspicious},
};

} // namespace

std::optional<avcore::DetectionEvent> CredentialTheftRule::Evaluate(const ProcessEvent& event,
                                                                    const ProcessTree& /*tree*/) const {
    return MatchCommandPatterns(Id(), kPatterns, event);
}

}  // namespace avbehavior
