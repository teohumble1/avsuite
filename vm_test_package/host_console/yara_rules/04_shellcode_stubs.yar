rule Shellcode_API_Resolution_Pattern
{
    meta:
        description = "Combination of injection APIs + C2 HTTP APIs common in shellcode loaders and reflective DLLs"
        severity = "malicious"
    strings:
        $va  = "VirtualAlloc"         ascii wide
        $vp  = "VirtualProtect"       ascii wide
        $crt = "CreateRemoteThread"   ascii wide
        $nct = "NtCreateThreadEx"     ascii wide
        $rut = "RtlCreateUserThread"  ascii wide
        $wpm = "WriteProcessMemory"   ascii wide
        $gpa = "GetProcAddress"       ascii wide
        $lla = "LoadLibraryA"         ascii wide
        $who = "WinHttpOpen"          ascii wide
        $whc = "WinHttpConnect"       ascii wide
        $whs = "WinHttpSendRequest"   ascii wide
    condition:
        // Allocation + exec (classic inject chain)
        (($va or $vp) and ($crt or $nct or $rut))
        // OR: dynamic resolution + HTTP C2
        or ($gpa and $lla and ($who or $whc or $whs))
        // OR: full reflective loader signature
        or (5 of ($va, $vp, $crt, $nct, $rut, $wpm, $gpa, $lla))
}
