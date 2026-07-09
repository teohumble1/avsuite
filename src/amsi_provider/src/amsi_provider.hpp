#pragma once

// CLSID: {14261D4E-E150-42C6-BD96-E27EFE322F86}
// Registered under HKLM\SOFTWARE\Microsoft\AMSI\Providers\{...} by DllRegisterServer.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>

#include <atomic>
#include <memory>
#include <string>

#include "avstaticscan/yara_engine.hpp"

namespace avamsi {

// {14261D4E-E150-42C6-BD96-E27EFE322F86}
static const CLSID CLSID_AvSuiteAmsiProvider = {
    0x14261d4e, 0xe150, 0x42c6,
    { 0xbd, 0x96, 0xe2, 0x7e, 0xfe, 0x32, 0x2f, 0x86 }
};

// Plain COM implementation of IAntimalwareProvider — no WRL dependency.
class AvAntimalwareProvider : public IAntimalwareProvider {
public:
    AvAntimalwareProvider();

    // IUnknown
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv) override;
    STDMETHOD_(ULONG, AddRef)() override;
    STDMETHOD_(ULONG, Release)() override;

    // IAntimalwareProvider
    STDMETHOD(Scan)(IAmsiStream* stream, AMSI_RESULT* result) override;
    STDMETHOD_(void, CloseSession)(ULONGLONG session) override;
    STDMETHOD(DisplayName)(LPWSTR* displayName) override;

private:
    std::atomic<ULONG> ref_count_{1};
    std::unique_ptr<avstaticscan::YaraEngine> yara_;
};

// Simple class factory for AvAntimalwareProvider
class AvAmsiClassFactory : public IClassFactory {
public:
    // IUnknown
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv) override;
    STDMETHOD_(ULONG, AddRef)() override;
    STDMETHOD_(ULONG, Release)() override;

    // IClassFactory
    STDMETHOD(CreateInstance)(IUnknown* outer, REFIID riid, void** ppv) override;
    STDMETHOD(LockServer)(BOOL lock) override;

private:
    std::atomic<ULONG> ref_count_{1};
};

// Global object count — used by DllCanUnloadNow
extern std::atomic<LONG> g_object_count;

} // namespace avamsi
