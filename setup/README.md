# TeoAvSuite Installer

Professional setup and distribution for TeoAvSuite antivirus/security scanning platform.

## For End-Users (Easiest Option)

### Portable Installer (Recommended)
**No installation of external tools required**

1. Download: `TeoAvSuite-v1.0.1-Portable.zip`
   - From: https://github.com/teohumble1/avsuite/releases
2. Extract ZIP file to any folder
3. Right-click `setup.bat` → **Run as Administrator**
4. Automatic installation to `C:\Program Files\TeoAvSuite`
5. Done! Run `avdashboard.exe`

**Files included:**
- `avdashboard.exe` - Main application
- `avconsolehost.exe` - Console host
- `avupdateserver.exe` - Update server
- `AvMiniFilter.sys` - Kernel driver
- `avsuite.json` - Configuration
- `setup.bat` - Setup script
- `README.md` - Full documentation

---

## For Developers (Building Custom Installer)

### Prerequisites
- **Inno Setup 6.x** - Download from https://jrsoftware.org/isdl.php
- Windows 10 or later
- Release build binaries (see ../build/release/)

### Step 1: Install Inno Setup
Download from: https://jrsoftware.org/isdl.php

### Step 2: Compile Installer

#### Option A: Using build-installer.ps1 (Recommended)
```powershell
cd .\setup
.\build-installer.ps1
```

#### Option B: GUI (Manual)
1. Open Inno Setup GUI
2. File → Open → Select `TeoAvSuite.iss`
3. Build → Compile

#### Option C: Command Line
```powershell
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" TeoAvSuite.iss
```

The compiled installer will be in `.\Output\TeoAvSuite-Setup-v1.0.1.exe`

## Installer Features

✅ **Installation**
- Installs to `C:\Program Files\TeoAvSuite` (default)
- Admin privileges required
- Windows 10/11 compatibility check
- Desktop shortcut option
- Start menu shortcuts

✅ **Components**
- avdashboard.exe (main application)
- Qt6 libraries (Core, Gui, Widgets)
- ML/AI libraries (GGML, Llama)
- Security libraries (OpenSSL, SQLite)
- YARA rules database
- Configuration files

✅ **Post-Installation**
- Automatic launch option
- Startup option (run on boot)
- Quick launch icon option

✅ **Uninstall**
- Clean removal of all files
- Registry cleanup
- YARA rules cleanup

## Distribution

Upload the compiled `.exe` to:
- GitHub Releases: https://github.com/teohumble1/avsuite/releases
- VirusTotal for scanning: https://www.virustotal.com/
- Distribution mirrors

## Version History

- **v1.0.1** (Current)
  - ✅ Portable installer (ZIP-based, no external dependencies)
  - ✅ AI Agent integration (Sentinel SIEM, Phi-3.5 LLM, EDRView, BehaviorMatrix)
  - ✅ Enhanced context-aware threat detection
  - ✅ Comprehensive documentation updates
  - ✅ GitHub Actions workflow for automated releases

- **v1.0.0** - Initial release
  - Realtime malware detection
  - YARA rule scanning
  - Quarantine management (with Select All + Batch operations)
  - AI threat analysis integration
  - ETW process monitoring

## File Descriptions

| File | Purpose |
|------|---------|
| `setup.bat` | Portable installer - copies files to Program Files (for end-users) |
| `build-installer.ps1` | Automates Inno Setup compilation (for developers) |
| `TeoAvSuite.iss` | Inno Setup configuration (for building .exe installer) |

## Distribution

### For End-Users
- **Primary**: Download portable ZIP from GitHub Releases
  - https://github.com/teohumble1/avsuite/releases
- **Install**: Run `setup.bat` as Administrator
- **No additional tools required**

### For Developers
- Build custom .exe installer using Inno Setup
- Or repackage components as needed
- Upload releases to GitHub, VirusTotal for scanning

## Support

Issues or questions?
- GitHub Issues: https://github.com/teohumble1/avsuite/issues
- GitHub Discussions: https://github.com/teohumble1/avsuite/discussions
- Email: vimh199@gmail.com

---

**Current Version**: v1.0.1
**Build Date**: 2026-07-10
**Installer Format**: Portable ZIP (primary) + Inno Setup 6.x (optional)
**Target OS**: Windows 11 x64 (Windows 10 may work)
**Status**: Ready for public distribution
