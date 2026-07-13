#pragma once

#include <string>

// Shared, hardened launcher for the "Apply" hardening scripts (Telemetry / Web /
// Fingerprint Guard). Consolidates the previously copy-pasted elevated
// ShellExecute calls and adds an anti-LPE gate: it refuses to run the script
// elevated if the script's directory is writable by non-administrators (i.e. a
// standard user could have swapped in a malicious script that our UAC prompt
// would then run as admin). See the security review finding #1.
namespace avsec {

// Launches `scriptFullPath` with `scriptArgs` elevated (UAC "runas") via
// powershell, but ONLY after verifying the containing directory is admin/SYSTEM
// write-only. On refusal it shows a MessageBox explaining why and does nothing.
// `scriptArgs` is appended after the -File argument (already-trusted constant
// flags from the caller, never user input). Returns true if the elevated
// process was launched.
bool RunElevatedHardeningScript(const std::wstring& scriptFullPath,
                                const std::wstring& scriptArgs);

// True only if we can positively confirm that no non-admin principal (Everyone,
// BUILTIN\Users, Authenticated Users) has write/delete access to `path`.
// Conservative: returns false when the ACL says a standard user can write.
bool IsAdminWriteOnly(const std::wstring& path);

} // namespace avsec
