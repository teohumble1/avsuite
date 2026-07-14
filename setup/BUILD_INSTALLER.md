# Building TeoAvSuite v1.0.6 Installer (Inno Setup)

This guide is for contributors who want to compile the Windows installer EXE.

## Requirements

- **Inno Setup 6+** — Download from https://jrsoftware.org/isdl.php
- **Windows 10/11** (x64)
- **AvSuite binaries already built** (avdashboard.exe, avamsi.dll, etc.)
- **~500 MB free disk space**

## Build Steps

### 1. Build AvSuite Binaries (Release)

From the project root:

```powershell
# Configure
cmake --preset=release -B build

# Build
cmake --build build --config Release --target avdashboard
cmake --build build --config Release --target avamsi
```

This produces:
- `build/release/src/dashboard_ui/Release/avdashboard.exe`
- `build/release/src/amsi_provider/Release/avamsi.dll`
- All DLLs + plugins (auto-copied to exe folder by CMake post-build rules)

### 2. Verify Build Artifacts

Check that these exist in `build/release/src/dashboard_ui/Release/`:
```
avdashboard.exe
platforms/qwindows.dll
yara_rules/
*.dll (Qt6, crypto, logging, etc.)
```

### 3. Compile Installer

Open **Inno Setup** compiler:

```powershell
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup\TeoAvSuite.iss
```

Or via GUI:
1. Open Inno Setup IDE
2. File → Open → `setup/TeoAvSuite.iss`
3. Build → Compile
4. Wait ~2-3 min (LZMA2 compression)

### 4. Verify Installer

Output EXE at: `setup/Output/TeoAvSuite-Setup-v1.0.6.exe`

```powershell
dir setup/Output/*.exe
# TeoAvSuite-Setup-v1.0.6.exe (~20-30 MB)
```

### 5. Test Installer

```powershell
# Extract to temp, verify install works
.\setup\Output\TeoAvSuite-Setup-v1.0.6.exe
```

Follow the wizard → Install to default location → Launch app.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Inno Setup not found** | Install from https://jrsoftware.org/isdl.php |
| **Missing avdashboard.exe** | Rebuild binaries first: `cmake --build build --config Release --target avdashboard` |
| **Compiler crashes (RAM)** | Machine has insufficient memory. Use a machine with ≥8GB RAM + stable CPU. |
| **"Path does not exist"** | Verify relative paths in `TeoAvSuite.iss` match your build output structure. |

## Config File

The installer ships `avsuite.default.json` (sanitized defaults, no API keys). On first install, it's copied to `%APPDATA%\TeoAvSuite\avsuite.json`. User customizations are preserved on upgrade.

## Troubleshooting Build Fails

If `cmake --build` fails:

1. **Clean rebuild:**
   ```powershell
   rm -Recurse -Force build
   cmake --preset=release -B build
   cmake --build build --config Release --target avdashboard
   ```

2. **Check CMake presets:**
   ```powershell
   cmake --list-presets
   ```

3. **Parallel build limits:** If compiler crashes, reduce parallelism:
   ```powershell
   cmake --build build --config Release --target avdashboard -j 2
   ```

## For CI/CD

Add to GitHub Actions / GitLab CI:

```yaml
- name: Build Installer
  run: |
    cmake --preset=release -B build
    cmake --build build --config Release --target avdashboard
    & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup\TeoAvSuite.iss
```

Then upload `setup/Output/TeoAvSuite-Setup-v1.0.6.exe` to releases.

---

**Questions?** File an issue at https://github.com/teohumble1/avsuite/issues
