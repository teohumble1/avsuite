// Detect binaries that embed hand-rolled x64 syscall stubs to bypass
// user-mode API hooks (EDR/AV hook at ntdll.dll level).
// Pattern: mov r10, rcx; mov eax, <syscall_nr>; syscall; ret
// Any single stub could be a coincidental match; >3 stubs means the binary
// is deliberately building its own syscall dispatch table.

rule Direct_Syscall_Stubs
{
    meta:
        description = "More than 3 x64 syscall stubs (4C 8B D1 B8 ?? ?? 00 00 0F 05 C3) -- binary builds its own syscall dispatch table to bypass ntdll.dll hooks"
        severity = "malicious"
    strings:
        // mov r10, rcx; mov eax, WORD (low byte = syscall_nr); syscall; ret
        // 4C 8B D1            = mov r10, rcx
        // B8 xx 00 00 00      = mov eax, syscall_nr  (nr < 256, high bytes = 0)
        // 0F 05               = syscall
        // C3                  = ret
        $stub = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }

        // Variant with 'test rcx,rcx' guard before the stub (SysWhispers2 style)
        $stub_sw2 = { 4C 8B D1 B8 ?? 00 00 00 F6 04 25 08 03 FE 7F 01 0F 05 C3 }
    condition:
        (#stub > 3) or (#stub_sw2 > 2) or (#stub + #stub_sw2 > 3)
}

rule Syscall_Stub_Any
{
    meta:
        description = "At least one x64 syscall stub present -- worth flagging even if count is low"
        severity = "suspicious"
    strings:
        $stub = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
    condition:
        #stub >= 1 and #stub <= 3
}
