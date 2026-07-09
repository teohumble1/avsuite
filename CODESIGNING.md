# AvSuite Driver Code-Signing Guide

## ⚠️ IMPORTANT: Portfolio Project - Self-Signed Only

This is a **research/portfolio project** using self-signed certificate. **NOT suitable for production.**

### Limitations:
- ❌ Self-signed (no chain of trust)
- ❌ No trusted CA endorsement
- ❌ Requires manual certificate installation or test-signing mode
- ❌ Not suitable for enterprise distribution
- ✅ Good for portfolio/research demonstration

### Two Ways to Use:

**Option 1: Manual Certificate Installation (Easier)**
- User installs certificate to Trusted Root once
- No SmartScreen warnings after
- Works for testing/portfolio demo

**Option 2: Enable Test-Signing Mode**
- Run: `bcdedit /set testsigning on` (admin)
- Driver signature not checked
- WARNING: Disables driver signature enforcement globally
- Only for development/testing

---

## Overview

AvSuite uses a self-signed code-signing certificate for the kernel-mode minifilter driver. This provides integrity verification and allows users to trust the driver after a one-time certificate installation.

## Certificate Details

- **Certificate File**: `avsuite_driver_cert.pfx`
- **Subject**: CN=AvSuite Driver
- **Valid Until**: 2036-07-09
- **Thumbprint**: AB07003BC9CB66C43896D9226A7D1BC138EC06F8
- **Store Location**: Trusted Root Certification Authorities (LocalMachine)

## Build & Signing

### Automatic Signing (Release Builds)

Release builds automatically sign the driver post-compilation:

```powershell
# Build will automatically sign: D:\Dev\AvSuite\driver\AvMiniFilter\x64\Release\AvMiniFilter.sys
msbuild AvMiniFilter.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Manual Signing

To manually sign a driver binary:

```powershell
D:\Dev\AvSuite\sign-driver.ps1 -DriverPath "path\to\AvMiniFilter.sys"
```

## User Installation

### Step 1: Install Certificate (One-time, requires Admin)

```powershell
# Run as Administrator
D:\Dev\AvSuite\install-cert.ps1
```

This installs the AvSuite driver certificate to the Trusted Root CA store, preventing SmartScreen warnings on future driver loads.

### Step 2: Install Driver

Once the certificate is installed, users can load the driver without SmartScreen warnings:

```powershell
sc.exe create AvMiniFilter binPath= "D:\path\to\AvMiniFilter.sys" type= kernel
net start AvMiniFilter
```

## First-Time User Experience

For users who haven't installed the certificate yet:

1. **First load**: Windows displays SmartScreen warning
2. **User action**: Click "More info" → "Run anyway"
3. **Driver loads**: Certificate installed after acceptance
4. **Future loads**: No warnings

## Distribution

When distributing AvSuite publicly:

1. Include `avsuite_driver_cert.pfx` and password in secure channel
2. Include `install-cert.ps1` with installer or documentation
3. Provide clear setup instructions in README
4. Consider bundling certificate installation into installer (ISS file)

## Technical Details

- **Algorithm**: SHA256
- **Timestamp Server**: http://timestamp.digicert.com
- **Key Length**: 2048-bit
- **Signature**: Embedded in driver binary PE header

## Verification

To verify a driver is correctly signed:

```powershell
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
& $signtool verify /pa "D:\Dev\AvSuite\driver\AvMiniFilter\x64\Release\AvMiniFilter.sys"
```

Note: Self-signed verification will show "root certificate is not trusted" until the certificate is installed in the Trusted Root CA store.
