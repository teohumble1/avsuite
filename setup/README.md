# TeoAvSuite Installer

Professional setup installer for TeoAvSuite antivirus/security scanning platform.

## Building the Installer

### Prerequisites
- **Inno Setup 6.x** - Download from https://jrsoftware.org/isdl.php
- Windows 10 or later

### Step 1: Install Inno Setup
Download and install from: https://jrsoftware.org/isdl.php

### Step 2: Compile Installer

#### Option A: GUI (Recommended)
1. Open Inno Setup GUI
2. File → Open → Select `TeoAvSuite.iss`
3. Build → Compile

#### Option B: Command Line
```powershell
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" TeoAvSuite.iss
```

The compiled installer will be in `.\Output\TeoAvSuite-Setup-v1.0.0.exe`

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

- **v1.0.0** - Initial release
  - Realtime malware detection
  - YARA rule scanning
  - Quarantine management (with Select All feature)
  - AI threat analysis
  - ETW process monitoring

## Support

Issues or questions?
- GitHub Issues: https://github.com/teohumble1/avsuite/issues
- Email: vimh199@gmail.com

---

**Build Date**: 2026-07-09
**Installer Format**: Inno Setup 6.x
**Target OS**: Windows 10/11
