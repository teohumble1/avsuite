#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <new>

#include "amsi_provider.hpp"

// STDAPI functions aren't exported from a DLL by default -- MSVC needs either
// a .def file or an explicit export directive. No .def file exists for this
// target, so export via linker pragma (x64 __stdcall has no name decoration,
// so the plain names below match exactly). Without this, regsvr32 fails with
// exit code 4 (GetProcAddress can't find DllRegisterServer).
#pragma comment(linker, "/EXPORT:DllGetClassObject=DllGetClassObject,PRIVATE")
#pragma comment(linker, "/EXPORT:DllCanUnloadNow=DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/EXPORT:DllRegisterServer=DllRegisterServer,PRIVATE")
#pragma comment(linker, "/EXPORT:DllUnregisterServer=DllUnregisterServer,PRIVATE")

BOOL APIENTRY DllMain(HMODULE hmod, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hmod);
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, avamsi::CLSID_AvSuiteAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) avamsi::AvAmsiClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return avamsi::g_object_count.load() == 0 ? S_OK : S_FALSE;
}

// ── Registration ─────────────────────────────────────────────────────────────

namespace {

std::wstring ThisDllPath() {
    wchar_t path[MAX_PATH] = {};
    HMODULE hmod = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&ThisDllPath), &hmod);
    GetModuleFileNameW(hmod, path, MAX_PATH);
    return path;
}

std::wstring ThisDllDir() {
    std::wstring p = ThisDllPath();
    const std::size_t slash = p.rfind(L'\\');
    return slash != std::wstring::npos ? p.substr(0, slash) : p;
}

HRESULT WriteRegSz(HKEY root, const wchar_t* subkey,
                   const wchar_t* value, const wchar_t* data) {
    HKEY hk = nullptr;
    if (RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE,
                        nullptr, &hk, nullptr) != ERROR_SUCCESS)
        return E_FAIL;
    const DWORD bytes = static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t));
    const LSTATUS rc = RegSetValueExW(hk, value, 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(data), bytes);
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS ? S_OK : E_FAIL;
}

} // namespace

STDAPI DllRegisterServer() {
    const std::wstring dll_path  = ThisDllPath();
    const std::wstring rules_dir = ThisDllDir() + L"\\rules";

    HRESULT hr = WriteRegSz(HKEY_CLASSES_ROOT,
        L"CLSID\\{14261D4E-E150-42C6-BD96-E27EFE322F86}\\InprocServer32",
        nullptr, dll_path.c_str());
    if (FAILED(hr)) return hr;

    hr = WriteRegSz(HKEY_CLASSES_ROOT,
        L"CLSID\\{14261D4E-E150-42C6-BD96-E27EFE322F86}\\InprocServer32",
        L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    hr = WriteRegSz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{14261D4E-E150-42C6-BD96-E27EFE322F86}",
        nullptr, L"AvSuite");
    if (FAILED(hr)) return hr;

    hr = WriteRegSz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AvSuite\\AmsiProvider",
        L"RulesDir", rules_dir.c_str());
    return hr;
}

STDAPI DllUnregisterServer() {
    RegDeleteTreeW(HKEY_CLASSES_ROOT,
        L"CLSID\\{14261D4E-E150-42C6-BD96-E27EFE322F86}");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{14261D4E-E150-42C6-BD96-E27EFE322F86}");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AvSuite\\AmsiProvider");
    return S_OK;
}
