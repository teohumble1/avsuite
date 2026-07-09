rule Reflective_Injection_API_Strings
{
    meta:
        description = "Plain-text presence of API names commonly resolved dynamically (GetProcAddress) for process injection -- catches payloads that avoid a static import table"
        severity = "suspicious"
    strings:
        $virtual_alloc = "VirtualAlloc" ascii wide
        $write_process_memory = "WriteProcessMemory" ascii wide
        $create_remote_thread = "CreateRemoteThread" ascii wide
        $get_proc_address = "GetProcAddress" ascii wide
        $load_library = "LoadLibraryA" ascii wide
    condition:
        3 of them
}
