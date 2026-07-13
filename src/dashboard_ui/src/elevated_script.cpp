#include "elevated_script.hpp"

#include <Windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>

#include <filesystem>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

namespace avsec {
namespace {

// Does `sid` have any write/delete/take-ownership right on the object described
// by `dacl`? Uses effective rights so inherited + group ACEs are all accounted.
bool SidCanWrite(PACL dacl, PSID sid) {
    if (!sid) return false;
    TRUSTEE_W t{};
    BuildTrusteeWithSidW(&t, sid);
    ACCESS_MASK rights = 0;
    if (GetEffectiveRightsFromAclW(dacl, &t, &rights) != ERROR_SUCCESS) {
        // Can't evaluate this principal — treat as "might be writable" so the
        // caller fails closed for well-known groups below.
        return true;
    }
    const ACCESS_MASK kWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA
                             | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | DELETE;
    return (rights & kWrite) != 0;
}

PSID MakeWellKnown(WELL_KNOWN_SID_TYPE type, BYTE* buf, DWORD bufLen) {
    DWORD sz = bufLen;
    if (!CreateWellKnownSid(type, nullptr, buf, &sz)) return nullptr;
    return reinterpret_cast<PSID>(buf);
}

} // namespace

bool IsAdminWriteOnly(const std::wstring& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    const DWORD rc = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION,
                                           nullptr, nullptr, &dacl, nullptr, &sd);
    if (rc != ERROR_SUCCESS || !dacl) {
        if (sd) LocalFree(sd);
        return false;  // can't prove it's safe -> treat as unsafe
    }

    BYTE everyone[SECURITY_MAX_SID_SIZE], users[SECURITY_MAX_SID_SIZE], auth[SECURITY_MAX_SID_SIZE];
    PSID sEveryone = MakeWellKnown(WinWorldSid, everyone, sizeof(everyone));
    PSID sUsers    = MakeWellKnown(WinBuiltinUsersSid, users, sizeof(users));
    PSID sAuth     = MakeWellKnown(WinAuthenticatedUserSid, auth, sizeof(auth));

    const bool writable = SidCanWrite(dacl, sEveryone)
                       || SidCanWrite(dacl, sUsers)
                       || SidCanWrite(dacl, sAuth);

    LocalFree(sd);
    return !writable;
}

bool RunElevatedHardeningScript(const std::wstring& scriptFullPath,
                                const std::wstring& scriptArgs) {
    // The script file must exist and neither it nor its directory may be
    // writable by a standard user (otherwise an attacker could swap the script
    // and have our UAC prompt run it as admin — local privilege escalation).
    std::error_code ec;
    if (!std::filesystem::exists(scriptFullPath, ec)) {
        MessageBoxW(nullptr,
                    L"Hardening script not found. Reinstall AvSuite.",
                    L"AvSuite", MB_ICONERROR | MB_OK);
        return false;
    }
    const std::wstring dir = std::filesystem::path(scriptFullPath).parent_path().wstring();
    if (!IsAdminWriteOnly(dir) || !IsAdminWriteOnly(scriptFullPath)) {
        MessageBoxW(nullptr,
                    L"Refused: the hardening script (or its folder) is writable by "
                    L"non-administrator users, which would let a local attacker run "
                    L"code as admin.\n\nInstall AvSuite under Program Files so its "
                    L"scripts are protected, then try again.",
                    L"AvSuite — elevation blocked", MB_ICONWARNING | MB_OK);
        return false;
    }

    // RemoteSigned (not Bypass): local install scripts still run, but anything
    // carrying a mark-of-the-web must be signed.
    std::wstring params = L"-NoProfile -ExecutionPolicy RemoteSigned -File \""
                        + scriptFullPath + L"\"";
    if (!scriptArgs.empty()) params += L" " + scriptArgs;

    const HINSTANCE rc = ShellExecuteW(nullptr, L"runas", L"powershell.exe",
                                       params.c_str(), nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

} // namespace avsec
