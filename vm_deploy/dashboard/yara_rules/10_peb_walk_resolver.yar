import "pe"

// Detect PEB-walk API resolution — used by Rust AV killers, shellcode, and
// C2 agents to find API addresses without using GetProcAddress (which AV hooks).
//
// Three approaches detected:
//   (A) gs:[60h] access = reading PEB pointer in x64 code
//   (B) ROR-13 instruction (0x0D) combined with a loop = ROR13 hash resolver
//   (C) Known API hash constants from widely-used hash tables (Cobalt Strike,
//       Metasploit beacon, common PoC code)

rule PEB_Walk_GS60_Access
{
    meta:
        description = "x64 code reads gs:[60h] (PEB pointer) with very few imports -- MSVC CRT legitimately uses gs:[60h] but always with many imports; low import count + PEB read = dynamic API resolver"
        severity = "malicious"
    strings:
        $peb_rax = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[60h]
        $peb_rcx = { 65 48 8B 0C 25 60 00 00 00 }  // mov rcx, gs:[60h]
        $peb_rdx = { 65 48 8B 14 25 60 00 00 00 }  // mov rdx, gs:[60h]
        $peb_r8  = { 65 4C 8B 04 25 60 00 00 00 }  // mov r8,  gs:[60h]
        $peb_r9  = { 65 4C 8B 0C 25 60 00 00 00 }  // mov r9,  gs:[60h]
    condition:
        pe.is_pe
        and (1 of ($peb_*))
        and pe.number_of_imports < 2  // legitimate CRT code always imports many things; boot tools have 2+
        and filesize > 100KB          // boot/system stubs (autofstx.exe ~88KB) are smaller; real loaders are bigger
}

rule PEB_Walk_ROR13_Hash_Resolver
{
    meta:
        description = "Binary contains ROR-13 rotation code combined with known API hash constants -- classic PEB-walk API resolution pattern"
        severity = "malicious"
    strings:
        // ROR instruction with immediate 13 (0x0D) -- the hash rotation
        $ror13_eax = { C1 C8 0D }        // ror eax, 13
        $ror13_ecx = { C1 C9 0D }        // ror ecx, 13
        $ror13_edx = { C1 CA 0D }        // ror edx, 13
        $ror13_ebx = { C1 CB 0D }        // ror ebx, 13
        $ror13_r8d = { 41 C1 C8 0D }     // ror r8d, 13
        $ror13_r9d = { 41 C1 C9 0D }     // ror r9d, 13

        // Well-known ROR13 additive hash constants (Metasploit/Cobalt Strike/PoC)
        // These are 32-bit LE representations embedded as immediates
        $hash_loadlib   = { 8E 4E 0E EC }  // LoadLibraryA    = 0xEC0E4E8E
        $hash_getproc   = { AA FC 0D 7C }  // GetProcAddress  = 0x7C0DFCAA
        $hash_virtalloc = { 91 BA 53 E5 }  // VirtualAlloc    = 0xE553BA91
        $hash_crremote  = { DD 9C BD 72 }  // CreateRemoteThread = 0x72BD9CDD
        $hash_winexec   = { 0E 8A FE 98 }  // WinExec         = 0x98FE8A0E
        $hash_exitproc  = { 56 A2 B5 7E }  // ExitProcess     = 0x7EB5A256
    condition:
        (1 of ($ror13_*)) and (2 of ($hash_*))
}

rule PEB_Walk_No_Imports
{
    meta:
        description = "PE has no kernel32/ntdll/api-ms imports yet is larger than 100 KB and has low entropy section count -- executable with zero standard imports + large binary + suspicious section entropy pattern suggests dynamic API resolution"
        severity = "malicious"
    strings:
        $mz       = { 4D 5A }
        $kernel32 = "KERNEL32" ascii wide nocase
        $ntdll    = "ntdll" ascii wide nocase
        $api_ms   = "api-ms-win" ascii wide nocase
        $ucrt     = "ucrtbase" ascii wide nocase
    condition:
        pe.is_pe
        and $mz at 0
        and not $kernel32
        and not $ntdll
        and not $api_ms
        and not $ucrt
        and filesize > 100KB
        and filesize < 10MB
        and pe.number_of_sections >= 3
        and for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 6.5
        )
}
