// Living-off-the-land / APT tradecraft: well-documented LOLBAS technique
// combinations (MITRE ATT&CK T1218/T1105/T1047/T1021), not attributed to any
// specific unverified campaign IOC. Each rule requires the specific flag/
// class/API combination that makes the technique work, not just the binary
// name alone (e.g. "mshta.exe" alone is meaningless -- mshta.exe legitimately
// exists on every Windows install).

rule Regsvr32_Squiblydoo_Remote_Scriptlet
{
    meta:
        description = "regsvr32 /i:http(s) remote scriptlet registration referencing scrobj.dll -- the documented 'Squiblydoo' AppLocker/whitelisting bypass (T1218.010)"
        severity = "critical"
    strings:
        $regsvr32   = "regsvr32" nocase
        $remote_reg = "/i:http" nocase
        $scrobj     = "scrobj.dll" nocase
    condition:
        all of them
}

rule Mshta_Remote_HTA_Execution
{
    meta:
        description = "mshta.exe invoked with an inline vbscript:/javascript: protocol handler pulling from a remote http(s) URL -- HTA-based remote code execution (T1218.005)"
        severity = "malicious"
    strings:
        $mshta  = "mshta.exe" nocase
        $vbs    = "vbscript:" nocase
        $js     = "javascript:" nocase
        $url    = /https?:\/\// nocase
    condition:
        $mshta and ($vbs or $js) and $url
}

rule Certutil_Download_Decode_Abuse
{
    meta:
        description = "certutil.exe used with -urlcache/-split (download) or -decode (base64 decode) -- documented LOLBIN abuse for fileless download/staging (T1105/T1140). Requires the literal .exe extension after the System32 audit showed a bare 'certutil' word plus these short flag strings can coincidentally co-occur inside large binary blobs (registry hive files)"
        severity = "malicious"
    strings:
        $certutil  = "certutil.exe" nocase
        $urlcache  = "-urlcache" nocase
        $split     = "-split" nocase
        $decode    = "-decode" nocase
    condition:
        $certutil and (($urlcache and $split) or $decode)
}

rule WMI_Remote_Connect_Process_Create
{
    meta:
        description = "WMI Win32_Process class combined with a remote ConnectServer call and ExecQuery -- remote process creation for lateral movement (T1047/T1021.003). Kept at suspicious, not malicious: the System32 audit found legitimate OEM/RMM management agents (e.g. Acer's AcerCCAgent.exe/AcerDIAgent.exe) use this exact combination for real remote hardware management"
        severity = "suspicious"
    strings:
        $wmi_proc = "Win32_Process" ascii wide
        $connect  = "ConnectServer" ascii wide
        $execq    = "ExecQuery" ascii wide
    condition:
        all of them
}

rule Remote_Service_Creation_PsExec_Style
{
    meta:
        description = "sc.exe binpath= flag combined with a literal ADMIN$ administrative-share UNC path -- remote service creation for lateral movement, the PsExec/sc.exe pattern (T1021.002/T1569.002)"
        severity = "malicious"
    strings:
        $binpath    = "binpath=" nocase
        $admin_share = "\\ADMIN$" ascii nocase
    condition:
        all of them
}

rule Rundll32_JavaScript_Protocol_Abuse
{
    meta:
        description = "rundll32.exe referenced alongside a javascript: protocol handler in the same binary -- the documented 'Rundll32 JavaScript Protocol' proxy-execution technique (T1218.011)"
        severity = "malicious"
    strings:
        $rundll  = "rundll32.exe" nocase
        $jsproto = "javascript:" nocase
    condition:
        all of them
}
