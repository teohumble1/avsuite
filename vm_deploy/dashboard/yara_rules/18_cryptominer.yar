// Cryptocurrency miner indicators: real stratum mining-protocol wire format,
// genuine XMRig (open-source, well-documented) config/CLI tokens, and GPU
// compute API combinations -- not generic words like "mining" or "coin".

rule Cryptominer_Stratum_JSONRPC_Handshake
{
    meta:
        description = "stratum+tcp(s):// mining-pool protocol URI combined with a real Stratum JSON-RPC method name (login/mining.subscribe) -- the actual wire handshake of a mining client, not just the word 'mining'"
        severity = "critical"
    strings:
        $stratum_tcp = "stratum+tcp://" ascii nocase
        $stratum_ssl = "stratum+ssl://" ascii nocase
        $method_login = "\"method\":\"login\"" ascii
        $method_sub   = "\"method\":\"mining.subscribe\"" ascii
    condition:
        ($stratum_tcp or $stratum_ssl) and ($method_login or $method_sub)
}

rule Cryptominer_XMRig_RandomX_Config_Markers
{
    meta:
        description = "XMRig's real JSON config fields (donate-level, rx/0 RandomX algorithm identifier, cpu) all present together -- XMRig is open-source and these exact token spellings are documented in its own source/config schema"
        severity = "critical"
    strings:
        $donate   = "\"donate-level\"" ascii
        $rx0      = "\"rx/0\"" ascii
        $cpu_field = "\"cpu\":" ascii
    condition:
        all of them
}

rule Cryptominer_GPU_Compute_Plus_Stratum
{
    meta:
        description = "GPU compute kernel APIs (CUDA/OpenCL) combined with a stratum mining-pool URI -- legitimate GPU compute applications (rendering, ML inference) have no reason to also speak the Stratum mining protocol"
        severity = "malicious"
    strings:
        $cuda = "cudaMalloc" ascii
        $cl1  = "clCreateBuffer" ascii
        $cl2  = "clEnqueueNDRangeKernel" ascii
        $stratum = "stratum+tcp://" ascii nocase
    condition:
        ($cuda or $cl1 or $cl2) and $stratum
}

rule Cryptominer_CLI_Flags_Combo
{
    meta:
        description = "XMRig's real command-line flag spellings (--donate-level combined with --cpu-max-threads-hint or --randomx) embedded as literal strings -- consistent with a statically-linked or argument-templated XMRig-derived miner"
        severity = "critical"
    strings:
        $donate_flag  = "--donate-level" ascii
        $threads_flag = "--cpu-max-threads-hint" ascii
        $randomx_flag = "--randomx" ascii
    condition:
        $donate_flag and ($threads_flag or $randomx_flag)
}

rule Cryptominer_Hidden_Process_Injection_Plus_Stratum
{
    meta:
        description = "Full process-injection API set (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) combined with a stratum mining URI -- a miner hiding itself inside another process rather than running as its own visible executable"
        severity = "critical"
    strings:
        $stratum = "stratum+tcp://" ascii nocase
        $valloc  = "VirtualAllocEx" ascii
        $wpm     = "WriteProcessMemory" ascii
        $crt     = "CreateRemoteThread" ascii
    condition:
        $stratum and $valloc and $wpm and $crt
}
