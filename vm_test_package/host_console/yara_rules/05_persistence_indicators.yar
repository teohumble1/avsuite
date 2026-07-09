rule Registry_Autorun_Persistence
{
    meta:
        description = "Registry Run/RunOnce/Winlogon keys written via reg.exe or script — common persistence mechanism"
        severity = "malicious"
    strings:
        $run_key      = "CurrentVersion\\Run"         nocase
        $runonce_key  = "CurrentVersion\\RunOnce"     nocase
        $winlogon_key = "Winlogon"                    nocase
        $reg_add      = "reg add"                     nocase
        $reg_hkcu     = "HKCU"                        nocase
        $reg_hklm     = "HKLM"                        nocase
    condition:
        $reg_add and ($run_key or $runonce_key or $winlogon_key)
        and ($reg_hkcu or $reg_hklm)
}

rule Scheduled_Task_Persistence
{
    meta:
        description = "schtasks /create with hidden PowerShell or download — dropper persistence"
        severity = "malicious"
    strings:
        $schtasks    = "schtasks"    nocase
        $create      = "/create"     nocase
        $ps_hidden   = "-w hidden"   nocase
        $ps_window   = "-WindowStyle Hidden" nocase
        $ps_noprof   = "-NonInteractive"     nocase
        $download    = "DownloadString"      nocase
        $iex         = "IEX"                 nocase
        $invoke      = "Invoke-Expression"   nocase
    condition:
        $schtasks and $create
        and (1 of ($ps_hidden, $ps_window, $ps_noprof))
        and (1 of ($download, $iex, $invoke))
}
