# AvSuite Reverse Engineering Guide

For security researchers wanting to analyze AvSuite internals.

---

## Binary Analysis

### IDA Pro Setup

```
File → Open
  ↓
Select: driver/AvMiniFilter/AvMiniFilter.sys
  ↓
File Type: PE executable (Auto-detect)
  ↓
Analysis Options:
  - Processor: x86-64
  - Create segment at entry point: YES
  - Load debug info if available: YES
```

### Key Functions to Find

```
1. AvmfFilterCreate
   - Location: .text section, early in binary
   - Purpose: Intercept file creation
   - Look for: FLT_PREOP_CALLBACK_STATUS return
   
2. AvmfFilterWrite
   - Purpose: Monitor write operations
   - Look for: WriteFile interception
   - Debug: Set breakpoint to watch operations

3. AvmfFilterDelete
   - Purpose: Track deletion events
   - Look for: File deletion logging

4. Communication Routines
   - Look for: Socket/network calls
   - Find: Message passing to user-mode
```

### Altitude Discovery

```
Search for: "385101" (our altitude)
Or: Look for USHORT constant declarations
   ↓
Right-click → "Convert to constant"
   ↓
Name: FilterAltitude
   ↓
This is the minifilter registration altitude
```

---

## GDB/WinDbg Debugging

### Setting Up Debugger

```
Prerequisites:
- Windows 11 Pro/Enterprise
- Test-signing enabled
- Administrator privileges
- Kernel debugger (WinDbg, Ghidra)

Start with:
  windbg -k net:port=50000,key=1.2.3.4
```

### Key Breakpoints

```
1. Driver Entry Point
   bp AvMiniFilter!DriverEntry
   g (go)
   
2. Filter Callback
   bp AvMiniFilter!AvmfPreCreateCallback
   g
   
   When hit:
   dt _FLT_CALLBACK_DATA @rcx (examine callback data)
   dd rax L10 (examine memory)

3. Altitude Registration
   bp FltRegisterFilter
   g
   
   When called:
   ? poi(rsp+8) (examine altitude parameter)
```

### Examining Callback Data

```
When AvmfPreCreateCallback is called:

1. Get FLT_CALLBACK_DATA structure
   dt _FLT_CALLBACK_DATA @rcx
   
2. Extract filename
   dt _FLT_CALLBACK_DATA @rcx -r
   
3. Get parent PID
   ? @rcx->Iopb->TargetFileObject->FsContext
   
4. Check operation type
   dd @rcx+0x20 (IRP operation offset)
```

---

## YARA Rules

Identify AvSuite driver characteristics:

```yara
rule AvSuite_Minifilter {
    strings:
        $altitude = "385101"
        $callback = "AvmfPreCreateCallback"
        $magic = {4D 5A 90 00}  // MZ header
    
    condition:
        all of them
}

rule AvSuite_Behavior_Pattern {
    strings:
        $pattern1 = "rule_shadow_copy_delete"
        $pattern2 = "rule_suspicious_parent_child"
    
    condition:
        2 of them
}
```

---

## Static Analysis (Ghidra)

```
1. Load binary into Ghidra
2. Auto-analyze (takes 2-5 minutes)
3. Search for functions:
   - DriverEntry: Initialization
   - FltRegisterFilter: Registration
   - Callbacks: Interception functions

4. Follow cross-references
   - Where is altitude used?
   - What data structures?
   - How is context stored?

5. Extract strings
   - Right-click → Defined Strings
   - Look for error messages (reveal logic)
```

---

## Memory Forensics

If AvSuite is running:

```
1. Dump running driver
   lm (list modules)
   .dump /f C:\dump.bin (full memory dump)

2. Analyze with Volatility
   volatility -f dump.bin dlllist -p [PID]
   volatility -f dump.bin memdump -p [PID] -D ./
   
3. Search for patterns
   strings dump.bin | grep "AvSuite"
   strings dump.bin | grep altitude
```

---

## Source Code Analysis

If you have source:

```c
// Key pattern to look for:

FLT_PREOP_CALLBACK_STATUS AvmfFilterCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    // This is the interception point
    // Rules are evaluated here
    
    // Return value determines verdict:
    // FLT_PREOP_SUCCESS_NO_CALLBACK  = Allow
    // FLT_PREOP_COMPLETE            = Block
    // FLT_PREOP_SUCCESS_WITH_CALLBACK = Log & Continue
}
```

---

## Evasion Analysis

Can you evade AvSuite detection?

### Known Evasion Techniques

1. **Kernel-Mode Rootkit**
   - AvSuite runs in Ring 0 but rootkit could run in Ring -1 (hypervisor)
   - Could hook AvSuite's callbacks
   - **Defense:** Secure Boot + HVCI (Hyper-V Code Integrity)

2. **Minifilter Unloading**
   - FltUnregisterFilter() could unload AvSuite
   - Only SYSTEM can do this (privilege required)
   - **Defense:** ACL protection on driver

3. **Memory Corruption**
   - Could overwrite AvSuite memory
   - Requires code execution first (detected by AvSuite)
   - **Defense:** Circular dependency

4. **Frequency-Based Evasion**
   - Very slow operations (1 file per hour) to avoid pattern detection
   - **Defense:** Still detected on shadow copy deletion (critical rule)

---

## Testing & Validation

### Test AvSuite Detection

```powershell
# Test 1: Can we create a process?
$proc = New-Object System.Diagnostics.Process
$proc.StartInfo.FileName = "notepad.exe"
$proc.Start()
# AvSuite should log this

# Test 2: Registry write?
Set-ItemProperty -Path "HKLM:\Software\..." -Name Test -Value 1
# AvSuite should intercept

# Test 3: Can we disable it?
# Try to kill service (requires admin)
Stop-Service AvMiniFilter -Force
# AvSuite should prevent this (ACL protected)
```

### Validation Results

Expected:
- ✅ All operations logged
- ✅ Cannot modify AvSuite settings
- ✅ Cannot unload driver
- ✅ Cannot disable service

---

## What You'll Learn

1. **Minifilter Architecture**
   - Altitude concept
   - Callback system
   - Data flow

2. **Windows Internals**
   - Driver loading process
   - Interrupt handling
   - Memory management at Ring 0

3. **Detection Logic**
   - How behavior patterns work
   - Why certain rules matter
   - Threat modeling decisions

4. **Security Concepts**
   - Process tree importance
   - Privilege escalation vectors
   - Malware evasion techniques

---

**Guide Version:** 1.0  
**Skill Level:** Intermediate (requires Windows internals knowledge)  
**Time Investment:** 10-20 hours to fully understand
