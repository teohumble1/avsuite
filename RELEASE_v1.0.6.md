# TeoAvSuite v1.0.6 Release

**Date:** 2026-07-14  
**Status:** Stable

## What's New

### Fixes
- **Dashboard UI compilation** — Fixed `BuildPageHeader` signature mismatch in Investigation Console
- **Event filter cleanup** — Removed unimplemented `eventFilter()` method to resolve linker errors
- **MSVC C1001 workaround** — Extended compiler heap + optimization flags for complex Qt template instantiations

### Performance (from v1.0.5)
- Low-end hardware detection (CPU cores ≤4, RAM <8GB, old GPU)
- Adaptive animations (skip on weak hardware)
- DLL Intel page: debounced search, optimized cell rendering, signature verification cache

### Features
- **Console Host** (`avconsolehost.exe`) — Lightweight endpoint monitor + behavior engine
- **Dashboard UI** (`avdashboard.exe`) — Rich Qt6 interface with real-time telemetry
- **Privacy Hardening Scripts** — Telemetry Guard, Fingerprint Guard, Web Guard automation

## Installation

### Option 1: Portable PowerShell Installer (Recommended)
```powershell
powershell -ExecutionPolicy Bypass -File Install-AvSuite-Portable.ps1
```

### Option 2: Manual Setup
1. Download `AvSuite-v1.0.6-portable.zip` from Releases
2. Extract to `C:\Program Files\TeoAvSuite\` (or preferred location)
3. Run `avdashboard.exe`

### Requirements
- **OS:** Windows 10/11 (build 19041+)
- **Architecture:** x64
- **Admin privileges** — for driver + policy installation

## Binaries

| File | Size | Purpose |
|------|------|---------|
| `avdashboard.exe` | 6.4 MB | Main UI dashboard |
| `avconsolehost.exe` | 1.4 MB | CLI/service endpoint |
| Runtime DLLs | ~15 MB | Qt6, crypto, logging |

## Known Issues

- **Dashboard full rebuild:** Requires non-degraded CPU (MSVC C1001 template instantiation limit on weak hardware)
- **Inno Setup installer:** Compile-only on stable machines (resource-intensive)

## Source

**GitHub:** https://github.com/teohumble1/avsuite  
**License:** MIT

## Changelog

### v1.0.5 → v1.0.6
- Telemetry Guard tab (live network monitoring + blocking)
- Web Guard tab (malicious JS detection)
- Performance optimization for all hardware tiers
- Security hardening (LPE via elevated scripts, driver whitelist bypass, rollback protection, quarantine safety)
- Cryptominer detection (3-part: behavior rules + network IOCs + CPU pegging banner)

---

**Built with:** CMake + MSVC 19.44 + Qt6 + vcpkg  
**Author:** TeoHumble Security  
**Status:** Ready for community distribution
