// C2 / botnet infrastructure indicators. Deliberately avoids guessing at
// specific historical campaign domains (those rotate and can't be verified
// here) -- relies instead on protocol-level artifacts, documented default
// tool fingerprints (Cobalt Strike default pipe names, a well-known Empire
// launcher stub), and API-combination heuristics.

rule C2_Cobalt_Strike_Default_SMB_Pipe
{
    meta:
        description = "Named pipe matching Cobalt Strike's documented default SMB Beacon pipe name prefixes (msagent_/MSSE-/status_) -- a well-known default fingerprint of unconfigured Cobalt Strike beacons"
        severity = "critical"
    strings:
        $pipe1 = "\\pipe\\msagent_" ascii wide nocase
        $pipe2 = "\\pipe\\MSSE-" ascii wide nocase
        $pipe3 = "\\pipe\\status_" ascii wide nocase
    condition:
        any of them
}

rule C2_Empire_PowerShell_Launcher_Stub
{
    meta:
        description = "Exact PowerShell-Empire default launcher argument stub ('-noP -sta -w 1 -enc') -- a documented, highly specific default that legitimate scripts have no reason to reproduce verbatim"
        severity = "critical"
    strings:
        $launcher = "-noP -sta -w 1 -enc" nocase
    condition:
        $launcher
}

rule C2_Malleable_Jquery_Profile_With_Injection
{
    meta:
        description = "A known default Cobalt Strike malleable-C2 profile URI (fake jquery-3.3.1.min.js) present in a binary that also imports process-injection APIs -- real jquery script files never import WriteProcessMemory/CreateRemoteThread/VirtualAllocEx"
        severity = "malicious"
    strings:
        $jq_uri = "/jquery-3.3.1.min.js" ascii nocase
        $inj1   = "WriteProcessMemory" ascii
        $inj2   = "CreateRemoteThread" ascii
        $inj3   = "VirtualAllocEx" ascii
    condition:
        $jq_uri and $inj1 and $inj2 and $inj3
}

rule C2_DNS_API_Without_Standard_HTTP_Stack
{
    meta:
        description = "Binary calls DNS query APIs but imports no WinHTTP stack at all -- weak heuristic for DNS-only C2 channels; some legitimate DNS-only tools (resolvers, diagnostics) will also match this, treat as a lead not a verdict"
        severity = "suspicious"
    strings:
        $dnsquery_a  = "DnsQuery_A" ascii
        $dnsquery_w  = "DnsQuery_W" ascii
        $dnsquery_ex = "DnsQueryEx" ascii
        $winhttp     = "WinHttpOpen" ascii
    condition:
        ($dnsquery_a or $dnsquery_w or $dnsquery_ex) and not $winhttp
}

rule C2_Raw_IP_Literal_HTTP_Endpoint_Plus_Injection
{
    meta:
        description = "Binary contacts a raw dotted-decimal IP-literal HTTP(S) endpoint and also imports process-injection APIs -- legitimate installers/updaters normally resolve a domain name rather than embedding a bare literal IP as their contact point"
        severity = "suspicious"
    strings:
        $ip_url = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $inj1   = "WriteProcessMemory" ascii
        $inj2   = "CreateRemoteThread" ascii
    condition:
        $ip_url and $inj1 and $inj2
}

rule C2_Reverse_Shell_CMD_Redirect
{
    meta:
        description = "cmd.exe referenced with a stderr-to-stdout shell redirect operator alongside raw Winsock socket creation -- the classic reverse-shell wiring pattern, rarely all present together outside actual shell payloads"
        severity = "malicious"
    strings:
        $cmd_exe = "cmd.exe" nocase
        $redirect = "2>&1" ascii
        $wsasocket = "WSASocketA" ascii
    condition:
        all of them
}
