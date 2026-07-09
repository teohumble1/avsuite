// Process hollowing (a.k.a. process replacement / RunPE):
//   1. Spawn a legitimate process in suspended state (CreateProcess)
//   2. Unmap the original image from its memory (NtUnmapViewOfSection)
//   3. Allocate and write injected code (VirtualAllocEx + WriteProcessMemory)
//   4. Redirect execution to the injected EP (SetThreadContext + ResumeThread)
//
// This technique bypasses process-based reputation checks because the visible
// process is a known-good binary (e.g., svchost.exe, explorer.exe).

rule Process_Hollowing_Full
{
    meta:
        description = "PE imports the complete process-hollowing API set -- spawn suspended + unmap + write + redirect execution"
        severity = "malicious"
    strings:
        $unmap1   = "NtUnmapViewOfSection" ascii
        $unmap2   = "ZwUnmapViewOfSection" ascii
        $wpm      = "WriteProcessMemory" ascii
        $cp_a     = "CreateProcessA" ascii
        $cp_w     = "CreateProcessW" ascii
        $set_ctx  = "SetThreadContext" ascii
        $resume   = "ResumeThread" ascii
    condition:
        ($unmap1 or $unmap2)
        and $wpm
        and ($cp_a or $cp_w)
        and $set_ctx
        and $resume
}

rule Process_Hollowing_Partial
{
    meta:
        description = "PE has NtUnmapViewOfSection + WriteProcessMemory or SetThreadContext -- partial hollowing signature (injected BOF, Cobalt Strike stage, or runner without full CreateProcess wrapper)"
        severity = "suspicious"
    strings:
        $unmap1  = "NtUnmapViewOfSection" ascii
        $unmap2  = "ZwUnmapViewOfSection" ascii
        $wpm     = "WriteProcessMemory" ascii
        $set_ctx = "SetThreadContext" ascii
        $resume  = "ResumeThread" ascii
        $cp_a    = "CreateProcessA" ascii
        $cp_w    = "CreateProcessW" ascii
    condition:
        ($unmap1 or $unmap2)
        and ($wpm or $set_ctx)
        // exclude the full combo (already caught by Process_Hollowing_Full)
        and not (($unmap1 or $unmap2) and $wpm and ($cp_a or $cp_w) and $set_ctx and $resume)
}
