import "pe"
import "math"

// Detect PE sections with cryptographic-level entropy — indicates packed or
// encrypted payload. Combined with low import count this is strongly malicious.
rule PE_High_Entropy_Section
{
    meta:
        description = "PE section with Shannon entropy > 7.0 and size > 4 KB -- packed or encrypted payload"
        severity = "suspicious"
    condition:
        pe.is_pe
        and for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0x1000
            and math.entropy(pe.sections[i].raw_data_offset,
                             pe.sections[i].raw_data_size) > 7.0
        )
}

rule PE_Packed_No_Imports
{
    meta:
        description = "PE with high-entropy section AND very few imports -- almost certainly a packed loader/dropper"
        severity = "malicious"
    condition:
        pe.is_pe
        and pe.number_of_imports < 3
        and for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0x1000
            and math.entropy(pe.sections[i].raw_data_offset,
                             pe.sections[i].raw_data_size) > 7.0
        )
}

rule PE_Encrypted_Code_Section
{
    meta:
        description = ".text section with entropy > 7.2 -- code section should not be this random; likely encrypted shellcode stub"
        severity = "malicious"
    condition:
        pe.is_pe
        and for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].name == ".text" or pe.sections[i].name == "CODE")
            and pe.sections[i].raw_data_size > 0x500
            and math.entropy(pe.sections[i].raw_data_offset,
                             pe.sections[i].raw_data_size) > 7.2
        )
}
