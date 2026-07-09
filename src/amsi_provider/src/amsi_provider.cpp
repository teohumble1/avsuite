#include "amsi_provider.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace avamsi {

std::atomic<LONG> g_object_count{0};

// ── Registry helper ──────────────────────────────────────────────────────────

namespace {

std::string GetRulesDir() {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\AvSuite\\AmsiProvider",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return {};
    wchar_t buf[MAX_PATH] = {};
    DWORD len = sizeof(buf);
    DWORD type = 0;
    const DWORD rc = RegQueryValueExW(hk, L"RulesDir", nullptr, &type,
                                       reinterpret_cast<LPBYTE>(buf), &len);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return {};
    return std::filesystem::path(buf).string();
}

} // namespace

// ── AvAntimalwareProvider ────────────────────────────────────────────────────

AvAntimalwareProvider::AvAntimalwareProvider() {
    ++g_object_count;
    const std::string rules_dir = GetRulesDir();
    if (!rules_dir.empty())
        yara_ = avstaticscan::YaraEngine::LoadRules(rules_dir);
}

HRESULT STDMETHODCALLTYPE AvAntimalwareProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, __uuidof(IAntimalwareProvider))) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AvAntimalwareProvider::AddRef() {
    return ++ref_count_;
}

ULONG STDMETHODCALLTYPE AvAntimalwareProvider::Release() {
    const ULONG r = --ref_count_;
    if (r == 0) {
        --g_object_count;
        delete this;
    }
    return r;
}

HRESULT STDMETHODCALLTYPE AvAntimalwareProvider::Scan(IAmsiStream* stream,
                                                       AMSI_RESULT* result) {
    if (!result) return E_INVALIDARG;
    *result = AMSI_RESULT_CLEAN;
    if (!stream || !yara_) return S_OK;

    // Get content size via GetAttribute
    ULONG64 content_size = 0;
    ULONG actual = 0;
    HRESULT hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE,
                                       sizeof(content_size),
                                       reinterpret_cast<PBYTE>(&content_size),
                                       &actual);
    if (FAILED(hr) || content_size == 0) return S_OK;

    // Cap at 16 MB — anything larger is almost certainly not a script
    static constexpr ULONG64 kMaxBytes = 16ull * 1024 * 1024;
    if (content_size > kMaxBytes) return S_OK;

    // Read content: Read(position, size, buffer, readSize)
    std::vector<unsigned char> buf(static_cast<std::size_t>(content_size));
    hr = stream->Read(0, static_cast<ULONG>(buf.size()), buf.data(), &actual);

    // Some AMSI streams (notably PowerShell's) don't implement Read() and
    // return E_NOTIMPL -- they expect providers to fall back to a direct
    // pointer via AMSI_ATTRIBUTE_CONTENT_ADDRESS instead (avoids a copy on
    // their end). This is documented provider behavior, not optional --
    // without it, every PowerShell-sourced scan silently sees zero bytes.
    if (hr == E_NOTIMPL) {
        PVOID content_address = nullptr;
        ULONG addr_actual = 0;
        hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS,
                                   sizeof(content_address),
                                   reinterpret_cast<PBYTE>(&content_address),
                                   &addr_actual);
        if (FAILED(hr) || !content_address) return S_OK;
        std::memcpy(buf.data(), content_address, buf.size());
        actual = static_cast<ULONG>(buf.size());
        hr = S_OK;
    }
    if (FAILED(hr) || actual == 0) return S_OK;

    // Get content name for labeling (best-effort)
    wchar_t name_buf[512] = {};
    ULONG name_actual = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME,
                          sizeof(name_buf),
                          reinterpret_cast<PBYTE>(name_buf), &name_actual);
    const std::string label = name_actual > 0
        ? std::filesystem::path(name_buf).string()
        : "[amsi_stream]";

    // Scan with YARA — promote any Malicious hit to AMSI_RESULT_DETECTED
    const auto detections = yara_->ScanBytes(
        reinterpret_cast<const std::uint8_t*>(buf.data()), actual, label);
    for (const auto& d : detections) {
        if (d.severity == avcore::Severity::Malicious) {
            *result = AMSI_RESULT_DETECTED;
            return S_OK;
        }
    }

    return S_OK;
}

void STDMETHODCALLTYPE AvAntimalwareProvider::CloseSession(ULONGLONG /*session*/) {
    // No per-session state
}

HRESULT STDMETHODCALLTYPE AvAntimalwareProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_INVALIDARG;
    const wchar_t kName[] = L"AvSuite Antimalware Provider";
    const std::size_t bytes = sizeof(kName);
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (!*displayName) return E_OUTOFMEMORY;
    std::memcpy(*displayName, kName, bytes);
    return S_OK;
}

// ── AvAmsiClassFactory ───────────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE AvAmsiClassFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AvAmsiClassFactory::AddRef() {
    return ++ref_count_;
}

ULONG STDMETHODCALLTYPE AvAmsiClassFactory::Release() {
    const ULONG r = --ref_count_;
    if (r == 0) delete this;
    return r;
}

HRESULT STDMETHODCALLTYPE AvAmsiClassFactory::CreateInstance(IUnknown* outer,
                                                              REFIID riid,
                                                              void** ppv) {
    if (!ppv) return E_POINTER;
    if (outer) return CLASS_E_NOAGGREGATION;
    auto* p = new (std::nothrow) AvAntimalwareProvider();
    if (!p) return E_OUTOFMEMORY;
    HRESULT hr = p->QueryInterface(riid, ppv);
    p->Release(); // QI added one ref; we release the constructor ref
    return hr;
}

HRESULT STDMETHODCALLTYPE AvAmsiClassFactory::LockServer(BOOL lock) {
    if (lock) ++g_object_count;
    else       --g_object_count;
    return S_OK;
}

} // namespace avamsi
