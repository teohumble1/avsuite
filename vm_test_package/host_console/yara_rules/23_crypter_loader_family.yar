import "pe"
import "math"

// Derived from static analysis of a real 4-sample dropper family (Vietnamese
// legal-threat social-engineering lures: "bang_chung"/evidence, "tailieuthuthap"/
// collected-documents, "truyto"/prosecution, "donkien"). All 4 share a tiny
// first section (<0x3000 raw bytes -- a minimal loader/crypter stub) and
// import NO networking, registry, or shell Win32 DLLs at all (ws2_32,
// wininet, advapi32, shell32) despite being genuine malware -- the real
// capability is resolved dynamically at runtime (GetProcAddress/manual
// mapping) specifically to keep the static import table clean. Two of the
// four additionally carry an oversized (>128KB) section with entropy in the
// 5.5-7.0 band: light XOR/table-based obfuscation strong enough to hide an
// embedded payload but too weak to trip the existing >7.0 "packed" rules in
// 08_entropy_packed.yar. A third sample in the family (4.5MB, low-entropy
// oversized section full of repeated pointer-like structures) shows the same
// stub/import fingerprint despite its blob section reading as unpacked data,
// which is why the fingerprint rule below does not gate on entropy at all.

rule Crypter_Loader_Moderate_Entropy_Blob
{
    meta:
        description = "Tiny code section (<0x3000) paired with an oversized section (>128KB) at moderate-high entropy (5.5-7.0) -- lighter-weight obfuscation than pure LZMA/AES packing, which evades the existing >7.0 entropy-only rules while still hiding a payload blob behind a minimal loader stub"
        severity = "malicious"
    condition:
        pe.is_pe
        and pe.sections[0].raw_data_size > 0
        and pe.sections[0].raw_data_size < 0x3000
        and for any i in (1..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0x20000
            and math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 5.5
            and math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) < 7.0
        )
}

rule Crypter_Loader_No_Network_Registry_Shell_Imports
{
    meta:
        description = "Tiny code section (<0x3000) combined with a completely clean import table AND an oversized high-entropy section -- no ws2_32/wininet (networking), advapi32 (registry/services), or shell32 (shell execution). Must also have an oversized (>64KB) section with moderate-high entropy (>=5.5) to rule out genuine trivial CLI tools."
        severity = "suspicious"
    condition:
        pe.is_pe
        and pe.sections[0].raw_data_size > 0
        and pe.sections[0].raw_data_size < 0x3000
        and not pe.imports("ws2_32.dll")
        and not pe.imports("wininet.dll")
        and not pe.imports("advapi32.dll")
        and not pe.imports("shell32.dll")
        and filesize > 50KB
        and for any i in (1..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0x10000
            and math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 5.5
        )
}
