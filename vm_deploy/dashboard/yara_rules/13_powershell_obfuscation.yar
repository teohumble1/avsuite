// 13_powershell_obfuscation.yar — PowerShell obfuscation & evasion detection
// Detects common encoding, variable replacement, and command obfuscation in PS scripts

rule PowerShell_Base64_Encoding {
    meta:
        description = "PowerShell base64-encoded command execution (common obfuscation)"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase ascii
        $b64a = "[System.Convert]::FromBase64String" nocase ascii
        $b64b = "System.Text.Encoding" nocase ascii
    condition:
        all of them
}

rule PowerShell_IEX_Download_Execute {
    meta:
        description = "IEX (Invoke-Expression) with web download (classic malware pattern)"
        severity = "critical"
    strings:
        $iex1 = "IEX" nocase ascii
        $iex2 = "Invoke-Expression" nocase ascii
        $download = "DownloadString" nocase ascii
    condition:
        any of ($iex*) and $download
}

rule PowerShell_Obfuscated_Variables {
    meta:
        description = "PowerShell variable name obfuscation (${} syntax evasion) with context heuristics to avoid binary false positives"
        severity = "high"
    strings:
        $ps_context1 = "powershell" nocase ascii
        $ps_context2 = "Get-Process" nocase ascii
        $ps_context3 = "[System." nocase ascii
        $var_obf = "${" ascii
        $random = /\$\{[A-Za-z0-9_]{15,}\}/ nocase
    condition:
        any of ($ps_context*) and (any of ($var_obf, $random))
}

rule PowerShell_WinAPI_Reflection {
    meta:
        description = "PowerShell using reflection to call Win32 APIs (unsafe API calls)"
        severity = "high"
    strings:
        $reflection = "[Reflection.Assembly]" nocase ascii
        $api_call = "GetMethod" nocase ascii
        $invoke = "Invoke" nocase ascii
    condition:
        all of them
}

rule PowerShell_Process_Injection_Technique {
    meta:
        description = "PowerShell process injection via WriteProcessMemory/CreateRemoteThread"
        severity = "critical"
    strings:
        $virt_alloc = "VirtualAlloc" nocase ascii
        $write_mem = "WriteProcessMemory" nocase ascii
        $remote_thread = "CreateRemoteThread" nocase ascii
    condition:
        all of them
}

rule PowerShell_Registry_Persistence {
    meta:
        description = "PowerShell modifying registry for persistence (HKLM/HKCU Run keys)"
        severity = "high"
    strings:
        $reg1 = "Set-ItemProperty" nocase ascii
        $reg2 = "HKLM:" nocase ascii
        $run_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii
    condition:
        all of them
}

rule PowerShell_EventLog_Clearing {
    meta:
        description = "PowerShell clearing Windows Event logs (defense evasion T1070.001)"
        severity = "high"
    strings:
        $clear1 = "Clear-EventLog" nocase ascii
        $clear2 = "Remove-Item" nocase ascii
        $log = "Security" nocase ascii
    condition:
        any of ($clear*) and $log
}

rule PowerShell_Credential_Dumping {
    meta:
        description = "PowerShell credential access (Get-LocalUser, Get-ADUser, LSASS dump)"
        severity = "high"
    strings:
        $cred1 = "Get-LocalUser" nocase ascii
        $cred2 = "Get-ADUser" nocase ascii
        $cred3 = "Invoke-Mimikatz" nocase ascii
    condition:
        any of them
}

rule PowerShell_AMSI_Bypass {
    meta:
        description = "PowerShell attempting to bypass AMSI (Antimalware Scan Interface)"
        severity = "critical"
    strings:
        $amsi1 = "AmsiInitFailed" nocase ascii
        $amsi2 = "[Ref].Assembly.GetType" nocase ascii
        $bypass = "SetValue" nocase ascii
    condition:
        any of ($amsi*) and $bypass
}

rule PowerShell_Network_Exfiltration {
    meta:
        description = "PowerShell exfiltrating data over HTTP/DNS (C2 communication)"
        severity = "high"
    strings:
        $net1 = "System.Net.WebClient" nocase ascii
        $net2 = "DownloadData" nocase ascii
        $http = "http://" nocase ascii
    condition:
        all of them
}
