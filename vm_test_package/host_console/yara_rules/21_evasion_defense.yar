// Defense-evasion technique combinations. Several of these APIs (debugger
// checks, sandbox artifact checks) are also used by legitimate DRM/anti-
// cheat/licensing code, so they're deliberately kept at "suspicious" rather
// than "malicious"/"critical" unless the combination is specific enough to
// have no realistic legitimate use (e.g. process-doppelganging's TxF combo).

rule Evasion_AMSI_DLL_Unload_Bypass
{
    meta:
        description = "amsi.dll referenced alongside FreeLibrary and GetModuleHandle -- the documented 'unload amsi.dll from this process' AMSI-bypass technique; legitimate AMSI-integrated software has no reason to free its own AMSI library"
        severity = "malicious"
    strings:
        $amsi_dll    = "amsi.dll" nocase
        $freelib     = "FreeLibrary" ascii
        $getmodule_a = "GetModuleHandleA" ascii
        $getmodule_w = "GetModuleHandleW" ascii
    condition:
        $amsi_dll and $freelib and ($getmodule_a or $getmodule_w)
}

rule Evasion_ETW_Provider_Tamper_Reference
{
    meta:
        description = "Both EtwEventWrite and the lower-level NtTraceEvent referenced together -- weak heuristic for deliberate ETW-level tampering/patching; legitimate tracing/telemetry libraries can also reference both, treat as a lead"
        severity = "suspicious"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
    condition:
        all of them
}

rule Evasion_Sandbox_VM_Artifact_Enumeration
{
    meta:
        description = "Two or more known sandbox/VM tooling process or module names (Sandboxie, VirtualBox, VMware) referenced alongside a module/window lookup API -- consistent with checking whether the binary is running in an analysis environment before continuing"
        severity = "suspicious"
    strings:
        $sbie   = "SbieDll.dll" nocase
        $vbox1  = "VBoxService.exe" nocase
        $vbox2  = "VBoxTray.exe" nocase
        $vmware = "vmtoolsd.exe" nocase
        $getmodule  = "GetModuleHandleA" ascii
        $findwindow = "FindWindowA" ascii
    condition:
        (2 of ($sbie, $vbox1, $vbox2, $vmware)) and ($getmodule or $findwindow)
}

rule Evasion_Debugger_Detection_Triple_Combo
{
    meta:
        description = "IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess all imported together -- a thorough anti-debug combo. Also common in legitimate DRM/anti-cheat/license-enforcement code, so this alone is a weak signal, not a verdict"
        severity = "suspicious"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
    condition:
        all of them
}

// NOTE: a "Evasion_Timing_Based_Analysis_Delay" rule (IsDebuggerPresent +
// Sleep + GetTickCount, all imported together) was removed after the
// System32 audit: it fired on 200 of ~a few thousand scanned files. That
// combination is simply too common in ordinary Windows software (retry
// loops, timeouts, licensing checks) to carry any discriminative value, and
// tightening it further would just reproduce Evasion_Debugger_Detection_
// Triple_Combo above. Not every plausible-sounding technique combo survives
// contact with a real corpus -- better to drop it than ship known noise.

rule Evasion_Process_Doppelganging_TxF_Abuse
{
    meta:
        description = "NtCreateTransaction + RollbackTransaction + CreateFileTransactedW all imported together -- the NTFS-transaction (TxF) API set used specifically for Process Doppelganging/Process Herpaderping. These three APIs have essentially no combined legitimate use outside that technique."
        severity = "critical"
    strings:
        $txf1 = "NtCreateTransaction" ascii
        $txf2 = "RollbackTransaction" ascii
        $txf3 = "CreateFileTransactedW" ascii
    condition:
        all of them
}
