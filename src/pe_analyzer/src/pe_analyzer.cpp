#include "avpe/pe_analyzer.hpp"

#include "avpe/authenticode.hpp"
#include "avcore/path_utils.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

namespace avpe {

namespace {

// Untrusted-input parser: every offset derived from the file itself is
// bounds-checked against the buffer before use. Files this rejects as
// malformed simply yield std::nullopt rather than undefined behavior.
constexpr size_t kMaxFileSizeBytes = 64ull * 1024 * 1024;

double ComputeEntropy(const std::uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    std::array<std::uint64_t, 256> counts{};
    for (size_t i = 0; i < size; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (std::uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / static_cast<double>(size);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool IsKnownPackerSectionName(const std::string& name) {
    static const std::array<const char*, 9> kPackerNames = {
        "upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", "fsg!", "mew", ".perplex",
    };
    const std::string lower = avcore::ToLowerAscii(name);
    return std::find(kPackerNames.begin(), kPackerNames.end(), lower) != kPackerNames.end();
}

std::string SectionNameToString(const BYTE raw[IMAGE_SIZEOF_SHORT_NAME]) {
    std::string name;
    for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME && raw[i] != 0; ++i) {
        name.push_back(static_cast<char>(raw[i]));
    }
    return name;
}

std::optional<size_t> RvaToFileOffset(const std::vector<IMAGE_SECTION_HEADER>& sections, std::uint32_t rva) {
    for (const auto& section : sections) {
        const std::uint32_t section_start = section.VirtualAddress;
        const std::uint32_t section_span = std::max(section.SizeOfRawData, section.Misc.VirtualSize);
        const std::uint32_t section_end = section_start + section_span;
        if (rva >= section_start && rva < section_end) {
            return static_cast<size_t>(section.PointerToRawData) + (rva - section_start);
        }
    }
    return std::nullopt;
}

std::string JoinCsv(const std::vector<std::string>& values) {
    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) oss << ", ";
        oss << values[i];
    }
    return oss.str();
}

} // namespace

std::optional<PeAnalysisResult> AnalyzeFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return std::nullopt;

    const std::streamsize size = file.tellg();
    if (size <= 0 || static_cast<size_t>(size) > kMaxFileSizeBytes) return std::nullopt;

    std::vector<std::uint8_t> buffer(static_cast<size_t>(size));
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return std::nullopt;

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

    const auto nt_offset = static_cast<std::uint32_t>(dos_header->e_lfanew);
    if (nt_offset == 0 || static_cast<size_t>(nt_offset) + sizeof(IMAGE_NT_HEADERS64) > buffer.size()) {
        return std::nullopt;
    }

    const auto* nt_signature = reinterpret_cast<const DWORD*>(buffer.data() + nt_offset);
    if (*nt_signature != IMAGE_NT_SIGNATURE) return std::nullopt;

    const auto* file_header =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer.data() + nt_offset + sizeof(DWORD));
    const auto* optional_magic = reinterpret_cast<const std::uint16_t*>(
        buffer.data() + nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    const bool is_pe32_plus = (*optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    IMAGE_DATA_DIRECTORY import_directory{};
    if (is_pe32_plus) {
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + nt_offset);
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < nt->OptionalHeader.NumberOfRvaAndSizes) {
            import_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    } else {
        if (nt_offset + sizeof(IMAGE_NT_HEADERS32) > buffer.size()) return std::nullopt;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + nt_offset);
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < nt->OptionalHeader.NumberOfRvaAndSizes) {
            import_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    }

    const size_t section_header_offset =
        static_cast<size_t>(nt_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader;
    const std::uint16_t num_sections = file_header->NumberOfSections;
    if (num_sections == 0 || num_sections > 96) return std::nullopt;
    if (section_header_offset + static_cast<size_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER) > buffer.size()) {
        return std::nullopt;
    }

    std::vector<IMAGE_SECTION_HEADER> sections(num_sections);
    std::memcpy(sections.data(), buffer.data() + section_header_offset,
                static_cast<size_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER));

    PeAnalysisResult result;

    for (const auto& section : sections) {
        const std::string name = SectionNameToString(section.Name);
        if (IsKnownPackerSectionName(name)) {
            result.packer_section_hits.push_back(name);
        }

        const size_t raw_start = section.PointerToRawData;
        const size_t raw_size = section.SizeOfRawData;
        if (raw_size == 0 || raw_start + raw_size > buffer.size()) continue;

        result.max_section_entropy = std::max(result.max_section_entropy,
                                               ComputeEntropy(buffer.data() + raw_start, raw_size));
    }

    std::set<std::string> imported_functions;
    if (import_directory.VirtualAddress != 0 && import_directory.Size != 0) {
        auto descriptor_offset = RvaToFileOffset(sections, import_directory.VirtualAddress);
        while (descriptor_offset && *descriptor_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= buffer.size()) {
            const auto* descriptor =
                reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + *descriptor_offset);
            if (descriptor->Name == 0 && descriptor->FirstThunk == 0) break;

            if (auto name_offset = RvaToFileOffset(sections, descriptor->Name); name_offset && *name_offset < buffer.size()) {
                result.imported_dlls.emplace_back(reinterpret_cast<const char*>(buffer.data() + *name_offset));
            }

            const std::uint32_t thunk_rva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk
                                                                            : descriptor->FirstThunk;
            auto thunk_offset = RvaToFileOffset(sections, thunk_rva);
            while (thunk_offset) {
                const size_t thunk_size = is_pe32_plus ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
                if (*thunk_offset + thunk_size > buffer.size()) break;

                std::uint64_t ordinal_flag_bit = 0;
                std::uint64_t address_of_data = 0;
                if (is_pe32_plus) {
                    const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(buffer.data() + *thunk_offset);
                    address_of_data = thunk->u1.AddressOfData;
                    ordinal_flag_bit = IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal) ? 1 : 0;
                } else {
                    const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(buffer.data() + *thunk_offset);
                    address_of_data = thunk->u1.AddressOfData;
                    ordinal_flag_bit = IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal) ? 1 : 0;
                }
                if (address_of_data == 0) break;

                if (ordinal_flag_bit == 0) {
                    if (auto import_name_offset = RvaToFileOffset(sections, static_cast<std::uint32_t>(address_of_data));
                        import_name_offset && *import_name_offset + sizeof(IMAGE_IMPORT_BY_NAME) <= buffer.size()) {
                        const auto* import_by_name =
                            reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(buffer.data() + *import_name_offset);
                        imported_functions.emplace(reinterpret_cast<const char*>(import_by_name->Name));
                    }
                }

                *thunk_offset += thunk_size;
            }

            *descriptor_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    result.is_signed = IsAuthenticodeSigned(path);
    result.total_import_count = static_cast<int>(imported_functions.size());

    // Classic Win32 injection chain
    const bool has_alloc =
        imported_functions.count("VirtualAlloc") || imported_functions.count("VirtualAllocEx");
    const bool has_write = imported_functions.count("WriteProcessMemory") > 0;
    const bool has_remote_thread =
        imported_functions.count("CreateRemoteThread") || imported_functions.count("CreateRemoteThreadEx");
    result.has_injection_import_combo = has_alloc && has_write && has_remote_thread;

    // NT-level injection (bypasses some user-mode hooks)
    const bool has_nt_thread =
        imported_functions.count("NtCreateThreadEx") || imported_functions.count("RtlCreateUserThread");
    const bool has_nt_alloc =
        imported_functions.count("NtAllocateVirtualMemory") || imported_functions.count("NtWriteVirtualMemory");
    result.has_nt_injection_combo = has_nt_thread && (has_alloc || has_nt_alloc);

    // Minimal-import loader: has VirtualProtect+CreateThread but deliberately
    // hides process/service APIs -- consistent with a Rust/C tool that resolves
    // APIs via PEB walk or direct syscall to evade import-table analysis.
    {
        const bool has_vp = imported_functions.count("VirtualProtect") > 0;
        const bool has_ct = imported_functions.count("CreateThread") > 0;
        const bool has_process_mgmt =
            imported_functions.count("OpenProcess") ||
            imported_functions.count("TerminateProcess") ||
            imported_functions.count("OpenSCManagerA") || imported_functions.count("OpenSCManagerW") ||
            imported_functions.count("RegOpenKeyExA") || imported_functions.count("RegOpenKeyExW");
        result.has_minimal_import_loader = has_vp && has_ct && !has_process_mgmt
                                           && result.total_import_count < 20;
    }

    // Process hollowing: spawn suspended + unmap original image + write payload
    // + redirect execution via SetThreadContext/ResumeThread.
    {
        const bool has_unmap =
            imported_functions.count("NtUnmapViewOfSection") ||
            imported_functions.count("ZwUnmapViewOfSection");
        const bool has_create_proc =
            imported_functions.count("CreateProcessA") ||
            imported_functions.count("CreateProcessW") ||
            imported_functions.count("CreateProcessInternalA") ||
            imported_functions.count("CreateProcessInternalW");
        const bool has_set_ctx  = imported_functions.count("SetThreadContext") > 0;
        const bool has_resume   = imported_functions.count("ResumeThread") > 0;
        result.has_hollowing_combo =
            has_unmap && has_write && has_create_proc && has_set_ctx && has_resume;
    }

    // Count suspicious API imports
    static const std::array<const char*, 24> kSuspiciousApis = {{
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtUnmapViewOfSection",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "SetWindowsHookExA", "SetWindowsHookExW",
        "OpenProcess", "MiniDumpWriteDump",
        "WinHttpOpen", "WinExec",
    }};
    for (const char* api : kSuspiciousApis) {
        if (imported_functions.count(api)) ++result.suspicious_import_count;
    }

    return result;
}

std::vector<avcore::DetectionEvent> ToDetectionEvents(const std::string& path, const PeAnalysisResult& result) {
    std::vector<avcore::DetectionEvent> events;

    if (!result.packer_section_hits.empty()) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.KNOWN_PACKER_SECTION";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Suspicious;
        event.target_path = path;
        event.evidence = "Known packer section name(s) found: " + JoinCsv(result.packer_section_hits);
        events.push_back(std::move(event));
    }

    if (result.max_section_entropy > 7.2) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.HIGH_ENTROPY_SECTION";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Suspicious;
        event.target_path = path;
        event.evidence = "Section entropy " + std::to_string(result.max_section_entropy)
                          + " (>7.2) -- likely packed or encrypted.";
        events.push_back(std::move(event));
    }

    if (result.has_injection_import_combo) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.INJECTION_IMPORT_COMBO";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = "Imports VirtualAlloc(Ex)+WriteProcessMemory+CreateRemoteThread(Ex) -- "
                          "classic process-injection capability.";
        events.push_back(std::move(event));
    }

    if (result.has_minimal_import_loader) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.MINIMAL_IMPORT_LOADER";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = "VirtualProtect+CreateThread in IAT but no process/service management APIs "
                         "(<20 total imports) -- consistent with a dynamic API resolver (PEB walk / syscall) "
                         "used by AV killers and shellcode loaders to hide their capabilities.";
        events.push_back(std::move(event));
    }

    if (result.has_nt_injection_combo) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.NT_INJECTION_COMBO";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = "Imports NT-level thread creation (NtCreateThreadEx/RtlCreateUserThread) "
                         "+ virtual memory APIs -- kernel-bypass process injection capability.";
        events.push_back(std::move(event));
    }

    if (result.has_hollowing_combo) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.PROCESS_HOLLOWING";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = "Imports complete process-hollowing API set: "
                         "NtUnmapViewOfSection+WriteProcessMemory+SetThreadContext+ResumeThread+CreateProcess "
                         "-- spawns a legitimate process suspended, replaces its code, then resumes it "
                         "to evade process-reputation checks.";
        events.push_back(std::move(event));
    }

    if (result.suspicious_import_count >= 8) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.MANY_SUSPICIOUS_IMPORTS";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = std::to_string(result.suspicious_import_count) +
                         " high-risk API imports (threshold 8) -- consistent with a loader or injector.";
        events.push_back(std::move(event));
    } else if (result.suspicious_import_count >= 5) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.MANY_SUSPICIOUS_IMPORTS";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Suspicious;
        event.target_path = path;
        event.evidence = std::to_string(result.suspicious_import_count) +
                         " high-risk API imports (threshold 5).";
        events.push_back(std::move(event));
    }

    if (result.max_section_entropy > 7.0 && result.total_import_count < 3) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.PACKED_NO_IMPORTS";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Malicious;
        event.target_path = path;
        event.evidence = "Section entropy " + std::to_string(result.max_section_entropy) +
                         " (>7.0) with only " + std::to_string(result.total_import_count) +
                         " import(s) -- likely packed or encrypted payload with stub loader.";
        events.push_back(std::move(event));
    }

    if (!result.is_signed && avcore::IsUnderUserWritableDir(path)) {
        avcore::DetectionEvent event;
        event.rule_id = "PE.UNSIGNED_IN_DROP_LOCATION";
        event.source = "pe_analyzer";
        event.severity = avcore::Severity::Suspicious;
        event.target_path = path;
        event.evidence = "Unsigned executable located in a user-writable drop location.";
        events.push_back(std::move(event));
    }

    return events;
}

} // namespace avpe
