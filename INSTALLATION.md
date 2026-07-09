# AvSuite Installation Guide

## Overview

AvSuite consists of two main components:
1. **AvMiniFilter.sys** - Kernel minifilter driver (signed)
2. **AvSuite.exe** - Interactive security dashboard

This guide covers deployment of both components.

## Prerequisites

- **OS**: Windows 11 (x64)
- **Admin Rights**: Required for driver installation
- **Storage**: ~500 MB for full installation
- **Memory**: 2+ GB RAM available

## Step 1: Certificate Installation (One-Time)

The AvSuite driver is signed with a self-signed certificate. Users must install this certificate once to avoid SmartScreen warnings on driver load.

### Automatic Installation

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File install-cert.ps1
```

**What this does:**
- Imports `avsuite_driver_cert.pfx` to Trusted Root Certification Authorities
- Password: `AvSuite2026` (prompted)
- Future driver loads will be trusted without warnings

### Manual Installation

If automated script fails:

```powershell
# Open Certificate Manager
certmgr.msc

# Right-click "Trusted Root Certification Authorities" → Import
# Select: avsuite_driver_cert.pfx
# Password: AvSuite2026
```

## Step 2: Driver Installation

### Quick Install (Batch Script)

```bash
# Run as Administrator
RUN_AS_ADMIN.bat
```

This will:
1. Install certificate
2. Copy driver to `C:\Windows\System32\drivers\AvMiniFilter.sys`
3. Create Windows service

### Manual Installation

```powershell
# 1. Copy driver
copy AvMiniFilter.sys C:\Windows\System32\drivers\

# 2. Create service (if doesn't exist)
sc create AvMiniFilter `
  binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" `
  type= kernel `
  start= auto

# 3. Start driver
net start AvMiniFilter
```

### Verify Installation

```powershell
# Check if service is running
sc query AvMiniFilter

# Verify minifilter is attached
fltmc instances | findstr AvMiniFilter

# Expected output:
# AvMiniFilter    C:    385101    AvMiniFilter Instance
```

## Step 3: Dashboard Installation

### Extract Files

```powershell
# Copy dashboard and dependencies
copy AvSuite.exe "C:\Program Files\AvSuite\"
copy *.dll "C:\Program Files\AvSuite\"
```

### Run Dashboard

```powershell
# Direct execution
C:\Program Files\AvSuite\AvSuite.exe

# Or via PowerShell
& "C:\Program Files\AvSuite\AvSuite.exe"
```

### First Launch

On first run, AvSuite will:
- Initialize local SQLite database
- Create configuration files
- Enumerate current system state
- Begin monitoring

## Step 4: Configuration

### Behavior Rules

Rules are configured in the behavior engine configuration file:
```
C:\ProgramData\AvSuite\rules.json
```

### Security Policies

Policy configuration:
```
C:\ProgramData\AvSuite\policies.json
```

### Log Location

Events are logged to:
```
C:\ProgramData\AvSuite\events.db
```

## Troubleshooting

### SmartScreen Warning on Driver Load

**Issue**: SmartScreen appears when starting driver

**Solution**: Install certificate using `install-cert.ps1` (Step 1)

### Driver Fails to Load

```powershell
# Check service status
net start AvMiniFilter

# View system event log
eventvwr.msc
# Navigate to Windows Logs → System
# Look for AvMiniFilter error messages
```

### Dashboard Crashes on Startup

1. Delete configuration files:
   ```powershell
   Remove-Item "C:\ProgramData\AvSuite\*" -Force
   ```

2. Restart dashboard:
   ```powershell
   C:\Program Files\AvSuite\AvSuite.exe
   ```

### Performance Issues

If CPU or memory usage is high:

1. Reduce monitoring rules (config file)
2. Increase database cleanup interval
3. Check enabled threat categories

## Uninstallation

### Remove Driver

```powershell
# Stop service
net stop AvMiniFilter

# Delete service
sc delete AvMiniFilter

# Remove driver file
del C:\Windows\System32\drivers\AvMiniFilter.sys

# Reboot
shutdown /r /t 0
```

### Remove Dashboard

```powershell
# Stop running instances
Stop-Process -Name AvSuite -Force

# Delete installation folder
Remove-Item "C:\Program Files\AvSuite" -Recurse -Force

# Delete configuration
Remove-Item "C:\ProgramData\AvSuite" -Recurse -Force
```

### Remove Certificate

```powershell
# Open Certificate Manager
certmgr.msc

# Navigate: Trusted Root Certification Authorities → Certificates
# Right-click "AvSuite Driver" → Delete
```

## Updates

### Automatic Updates

AvSuite includes a self-update mechanism:

1. Check for updates: Dashboard → Settings → Check for Updates
2. Download signed binary
3. Verify signature
4. Apply update on next restart

### Manual Updates

```powershell
# Download new version
# Copy new AvSuite.exe over existing

# For driver updates:
# 1. Stop driver: net stop AvMiniFilter
# 2. Copy new AvMiniFilter.sys to System32/drivers
# 3. Restart: net start AvMiniFilter
```

## Security Notes

- Driver requires administrator privileges
- SmartScreen warnings eliminated after certificate installation
- All driver operations are logged
- Local database is suitable for offline operation
- No internet connectivity required

## Support

For issues or questions:
1. Check README.md for feature overview
2. See CODESIGNING.md for certificate details
3. Review VMWARE_TEST_CHECKLIST.md for known good states
4. Check Windows Event Viewer for driver errors

---

**Version**: 1.0  
**Last Updated**: 2026-07-09  
**Certificate Valid Until**: 2036-07-09
