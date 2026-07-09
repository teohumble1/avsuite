#include "avpe/authenticode.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// WIN32_LEAN_AND_MEAN excludes wincrypt.h from windows.h's normal include
// chain, but mscat.h/softpub.h reference its legacy CAPI types (HCRYPTPROV,
// CRYPT_HASH_BLOB, ...) without including it themselves -- must come first.
#include <wincrypt.h>
#include <bcrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")

namespace avpe {

namespace {

std::wstring WidenUtf8(const std::string& narrow) {
    const int wide_len = MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) return std::wstring();
    std::wstring wide(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), -1, wide.data(), wide_len);
    if (!wide.empty() && wide.back() == L'\0') wide.pop_back(); // drop the embedded NUL terminator MultiByteToWideChar wrote
    return wide;
}

bool VerifyEmbeddedSignature(const std::wstring& wide_path) {
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide_path.c_str();

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.pFile = &file_info;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy_guid, &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy_guid, &trust_data);

    return status == ERROR_SUCCESS;
}

std::wstring HashToUpperHex(const std::vector<BYTE>& hash) {
    static const wchar_t kHexDigits[] = L"0123456789ABCDEF";
    std::wstring hex;
    hex.reserve(hash.size() * 2);
    for (BYTE b : hash) {
        hex.push_back(kHexDigits[b >> 4]);
        hex.push_back(kHexDigits[b & 0x0F]);
    }
    return hex;
}

// Most Windows OS component binaries (e.g. notepad.exe) are not individually
// Authenticode-signed -- they're validated against a system catalog (.cat)
// file instead. VerifyEmbeddedSignature() alone would wrongly report these
// as unsigned; this mirrors what `Get-AuthenticodeSignature` and Sysinternals
// Sigcheck do for catalog-signed files.
bool VerifyCatalogSignature(const std::wstring& wide_path) {
    const HANDLE file_handle = CreateFileW(wide_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) return false;

    bool verified = false;
    HCATADMIN cat_admin = nullptr;
    // DRIVER_ACTION_VERIFY is a raw struct-initializer macro (like
    // WINTRUST_ACTION_GENERIC_VERIFY_V2 below), not an addressable variable
    // -- it must be copy-initialized into a local first.
    GUID subsystem_guid = DRIVER_ACTION_VERIFY;
    if (CryptCATAdminAcquireContext2(&cat_admin, &subsystem_guid, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
        DWORD hash_size = 0;
        CryptCATAdminCalcHashFromFileHandle2(cat_admin, file_handle, &hash_size, nullptr, 0);

        if (hash_size > 0) {
            std::vector<BYTE> hash(hash_size);
            if (CryptCATAdminCalcHashFromFileHandle2(cat_admin, file_handle, &hash_size, hash.data(), 0)) {
                const HCATINFO cat_info = CryptCATAdminEnumCatalogFromHash(cat_admin, hash.data(), hash_size, 0, nullptr);
                if (cat_info) {
                    CATALOG_INFO catalog_info = {};
                    catalog_info.cbStruct = sizeof(catalog_info);
                    if (CryptCATCatalogInfoFromContext(cat_info, &catalog_info, 0)) {
                        const std::wstring member_tag = HashToUpperHex(hash);

                        WINTRUST_CATALOG_INFO wt_catalog_info = {};
                        wt_catalog_info.cbStruct = sizeof(wt_catalog_info);
                        wt_catalog_info.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
                        wt_catalog_info.pcwszMemberFilePath = wide_path.c_str();
                        wt_catalog_info.pcwszMemberTag = member_tag.c_str();
                        wt_catalog_info.pbCalculatedFileHash = hash.data();
                        wt_catalog_info.cbCalculatedFileHash = hash_size;
                        wt_catalog_info.hCatAdmin = cat_admin;

                        DRIVER_VER_INFO driver_ver_info = {};
                        driver_ver_info.cbStruct = sizeof(driver_ver_info); // presence alone disables OS-version checks

                        GUID policy_guid = DRIVER_ACTION_VERIFY;
                        WINTRUST_DATA trust_data = {};
                        trust_data.cbStruct = sizeof(trust_data);
                        trust_data.dwUIChoice = WTD_UI_NONE;
                        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
                        trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
                        trust_data.pCatalog = &wt_catalog_info;
                        trust_data.pPolicyCallbackData = &driver_ver_info;

                        const LONG status =
                            WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy_guid, &trust_data);
                        verified = (status == ERROR_SUCCESS);

                        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy_guid, &trust_data);
                    }
                    CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(cat_admin, 0);
    }

    CloseHandle(file_handle);
    return verified;
}

} // namespace

bool IsAuthenticodeSigned(const std::string& path) {
    const std::wstring wide_path = WidenUtf8(path);
    if (wide_path.empty()) return false;

    if (VerifyEmbeddedSignature(wide_path)) return true;
    return VerifyCatalogSignature(wide_path);
}

} // namespace avpe
