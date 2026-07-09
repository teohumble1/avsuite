# AvSuite VMware Testing Checklist

## Pre-Deployment Verification ✓

- [x] Driver binary signed with AvSuite certificate
- [x] Certificate valid until 2036-07-09
- [x] Timestamp server: DigiCert (trusted)
- [x] Signature embedded in PE header
- [x] Post-build signing configured in Visual Studio project
- [x] Certificate PFX exported: `avsuite_driver_cert.pfx`

## VM Testing Steps

### 1. Certificate Installation (Run as Administrator)

```powershell
# In VM command line as Administrator
powershell.exe -ExecutionPolicy Bypass -File "setup.ps1"
```

**Expected Results:**
- Certificate installed to Trusted Root CA
- Driver copied to System32\drivers
- No SmartScreen warnings on subsequent loads

### 2. Driver Loading

```powershell
# Create service entry (if not already done)
sc.exe create AvMiniFilter binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" type= kernel

# Start driver
net start AvMiniFilter
```

**Expected Results:**
- Driver loads successfully
- No Windows security warnings
- Service status: "Started"

### 3. Verify Loaded Driver

```powershell
# Check if minifilter is attached
fltmc.exe instances

# Should show AvMiniFilter in the instance list
```

### 4. Test Behavior Engine

After driver loads, test:
- [ ] File operations monitored
- [ ] Registry operations monitored
- [ ] Process monitoring working
- [ ] Blocking verdicts applied
- [ ] Event logging to database

### 5. Test Self-Update Mechanism

```powershell
# Create new signed binary (manually or via CI)
# Run updater to fetch new version
# Verify signature validation
# Verify seamless update
```

**Expected Results:**
- Update validates signed binary
- No prompts or warnings
- Service continues without restart
- Version updated successfully

### 6. Unload & Verify Certificate Trust

```powershell
# Stop driver
net stop AvMiniFilter

# Reinstall fresh driver from same location
net start AvMiniFilter

# No SmartScreen warnings on reload
```

## Rollback Procedure

If issues occur:

```powershell
# Stop driver
net stop AvMiniFilter

# Remove service
sc.exe delete AvMiniFilter

# Remove from System32\drivers
Remove-Item C:\Windows\System32\drivers\AvMiniFilter.sys

# Revert to previous snapshot
# OR restore from backup
```

## Success Criteria

- ✓ No SmartScreen warnings after certificate installation
- ✓ Driver loads on demand without manual intervention
- ✓ Minifilter properly attached
- ✓ Behavior engine rules fire as expected
- ✓ Self-update mechanism validates and applies new signed binaries
- ✓ Clean unload/reload cycle

## Notes

- First deployment will show SmartScreen warning (expected)
- Subsequent deployments should have zero warnings (verify certificate installation)
- Certificate expires 2036-07-09 (10-year validity)
- Deployment ready for: public distribution, installer packaging, CI/CD pipelines
