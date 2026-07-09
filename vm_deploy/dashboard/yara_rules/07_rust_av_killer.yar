import "pe"
import "math"

rule Rust_Minimal_Import_Loader
{
    meta:
        description = "Rust/C binary with VirtualProtect+CreateThread but no process/service management APIs in IAT -- consistent with a loader that resolves APIs dynamically via PEB walk or direct syscall to evade import analysis"
        severity = "malicious"
    strings:
        $rust1 = "Rust" ascii
        $rust2 = "rust_" ascii
        $rust3 = ".pdata" ascii   // Rust x64 always emits .pdata
        $vp    = "VirtualProtect" ascii
        $ct    = "CreateThread" ascii
        $open_process = "OpenProcess" ascii
        $open_sc      = "OpenSCManager" ascii
        $reg_open     = "RegOpenKey" ascii
        $terminate    = "TerminateProcess" ascii
    condition:
        ($rust1 or $rust2 or $rust3)
        and $vp and $ct
        and not $open_process
        and not $open_sc
        and not $reg_open
        and not $terminate
        and filesize > 100KB
}

rule Large_Encrypted_RData_Section
{
    meta:
        description = "PE where .rdata section is >75% of total file size AND entropy >6.5 -- embedded encrypted payload or obfuscated string pool (vukhi_diet_av.exe pattern: 94% .rdata)"
        severity = "suspicious"
    condition:
        pe.is_pe
        and filesize > 50KB
        and for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".rdata"
            and pe.sections[i].raw_data_size > 50000
            and pe.sections[i].raw_data_size * 4 > filesize * 3
            and math.entropy(pe.sections[i].raw_data_offset,
                             pe.sections[i].raw_data_size) > 6.5
        )
}
