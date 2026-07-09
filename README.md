# AvSuite - Windows Kernel Security Research Project

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue)
![Status](https://img.shields.io/badge/status-Research%20Project-blue)
![License](https://img.shields.io/badge/license-Portfolio-gray)

A portfolio security research project demonstrating Windows kernel-mode threat detection and behavior analysis. **Not for production use.**

## What This Is

This is an **educational/research project** that implements:
- Kernel minifilter driver (WDM architecture)
- Behavior-based threat detection patterns
- Real-time filesystem monitoring
- Self-signed code-signing infrastructure

**This is NOT production antivirus.** It demonstrates systems programming and security architecture knowledge.

## Technical Implementation

### Kernel Driver
- **Language**: C
- **Architecture**: WDM minifilter
- **Size**: 16.6 KB (optimized)
- **Status**: Functional, tested on Windows 11 VMware
- **Signing**: Self-signed certificate (SHA256)

### Behavior Engine
- Configurable pattern detection
- File/registry/process monitoring
- Event logging to SQLite database
- Real-time decision making

### Testing
- EICAR standard test file
- 50+ benign file monitoring
- No system crashes
- Stable operation verified

## What's Implemented ✅

- Minifilter driver (loads, attaches, functional)
- Basic behavior rule engine
- Self-signed code-signing
- Event database logging
- Installation procedures
- VMware testing validated

## What's NOT Implemented ❌

- Real malware testing (zero samples tested)
- False positive minimization (no benign corpus)
- Performance optimization
- Evasion resistance
- Enterprise features
- Production-grade reliability

## Quick Start

### Prerequisites
- Windows 11 (x64)
- Administrator access
- Visual Studio 2022 (to rebuild)

### Install Driver

1. Install certificate:
```powershell
Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation Cert:\LocalMachine\Root -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
```

2. Copy driver:
```cmd
copy AvMiniFilter.sys C:\Windows\System32\drivers\
```

3. Create service:
```cmd
sc create AvMiniFilter binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" type= kernel
```

4. Start:
```cmd
net start AvMiniFilter
```

5. Verify:
```cmd
fltmc instances
```

## Important Limitations

### Security
- **Self-signed certificate only** - not from trusted CA
- No real malware tested against
- Not resistant to sophisticated evasion
- No zero-day detection capability

### Performance
- Not optimized for production workloads
- Simplified rule evaluation
- No caching mechanisms
- Not benchmarked under load

### Completeness
- Dashboard UI is framework-level only
- ETW integration incomplete
- No machine learning models
- Limited threat pattern coverage

## Testing Results

**Real test execution (2026-07-09):**
- EICAR standard test file: ✅ Created
- Benign files (50): ✅ Monitored
- Driver instances: ✅ 3 active on C: drive
- System stability: ✅ No crashes
- Altitude: 385101 ✅ Correct

**Important note:** This is NOT comprehensive testing. Real AV requires:
- 1M+ real malware samples
- 1M+ benign application binaries
- False positive rate evaluation
- Performance stress testing
- Evasion technique resistance

## Code Quality

- Professional C/C++ implementation
- Clean architecture (kernel + user-mode)
- Proper error handling
- Security best practices (no secrets in repo)
- Well-documented code

## For Portfolio Review

### What This Demonstrates
✅ Windows kernel programming
✅ Driver development knowledge
✅ Security architecture design
✅ Code-signing practices
✅ Professional documentation
✅ Realistic scoping

### What This Does NOT Claim
❌ Production-ready antivirus
❌ Enterprise-grade reliability
❌ Tested on real malware
❌ Zero false positives
❌ Performance-optimized

## Files

- `driver/AvMiniFilter/` - Kernel driver source + binary
- `src/` - Core engine code
- `.gitignore` - Protects secrets (*.pfx, etc)
- `STATUS.md` - Component completion tracking
- `TEST-RESULTS.md` - Real testing data

## Interview Talking Points

**"Is this production-ready?"**
> No - it's a research project to demonstrate kernel architecture and security concepts. Production AV needs months of malware testing and false positive tuning.

**"Why self-signed certificate?"**
> For portfolio purposes. Production would use EV certificate from trusted CA. The important part is showing I understand code-signing practices.

**"How would you make it production?"**
> Real malware corpus testing, false positive minimization, performance optimization, enterprise features - that's 6-12 months of team work.

## Learning Resources

See `STATUS.md` for detailed component breakdown of what's complete vs. what's framework-level.

## Author

Teohumble - Security Research & Development

---

**Project Status**: Research/Portfolio  
**Platform**: Windows 11  
**Build Status**: Clean (Debug + Release)  
**Testing**: VMware validated  
**Repository**: https://github.com/teohumble1/avsuite
