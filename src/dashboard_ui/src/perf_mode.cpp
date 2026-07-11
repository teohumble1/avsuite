#include "perf_mode.hpp"

#include <thread>
#include <cstring>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <dxgi.h>

#pragma comment(lib, "dxgi.lib")

namespace avdashboard {
namespace {

bool DetectLowEnd() {
    // Manual override, for machines the heuristic misjudges or for QA testing the
    // low-end path on capable hardware: AVSUITE_PERF_MODE=low forces low-end,
    // =full forces the full-effect path. Anything else falls through to detection.
    char buf[16] = {};
    if (GetEnvironmentVariableA("AVSUITE_PERF_MODE", buf, sizeof(buf)) > 0) {
        if (_stricmp(buf, "low") == 0)  return true;
        if (_stricmp(buf, "full") == 0) return false;
    }

    // 1) CPU: <= 4 logical cores is a low-end / older laptop.
    const unsigned cores = std::thread::hardware_concurrency();
    if (cores != 0 && cores <= 4) return true;

    // 2) RAM: < 8 GB total physical memory.
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        const unsigned long long gb = ms.ullTotalPhys / (1024ull * 1024 * 1024);
        if (gb < 8) return true;
    }

    // 3) GPU: pick the adapter with the most dedicated VRAM. A best adapter with
    //    little dedicated video memory is an old/integrated GPU that struggles
    //    with heavy per-frame raster effects (QGraphicsEffect, 60fps repaints).
    IDXGIFactory* factory = nullptr;
    if (SUCCEEDED(CreateDXGIFactory(__uuidof(IDXGIFactory),
                                    reinterpret_cast<void**>(&factory))) &&
        factory) {
        SIZE_T best_vram = 0;
        IDXGIAdapter* adapter = nullptr;
        for (UINT i = 0; factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
            DXGI_ADAPTER_DESC desc{};
            if (SUCCEEDED(adapter->GetDesc(&desc)) &&
                desc.DedicatedVideoMemory > best_vram) {
                best_vram = desc.DedicatedVideoMemory;
            }
            adapter->Release();
            adapter = nullptr;
        }
        factory->Release();
        // Conservative: only flag when we have a real, small reading (< 512 MB).
        if (best_vram > 0 && best_vram < (512ull * 1024 * 1024)) return true;
    }

    return false;
}

} // namespace

bool IsLowEndSystem() {
    static const bool low = DetectLowEnd();
    return low;
}

int AnimMs(int normal_ms) {
    return IsLowEndSystem() ? 0 : normal_ms;
}

} // namespace avdashboard
